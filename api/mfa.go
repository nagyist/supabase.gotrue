package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/netlify/gotrue/crypto"
	"github.com/netlify/gotrue/models"
	"github.com/netlify/gotrue/storage"
	"github.com/pquerna/otp/totp"
	"image/png"
	"net/http"
	"time"
)

type EnrollFactorParams struct {
	FactorSimpleName string `json:"factor_simple_name"`
	FactorType       string `json:"factor_type"`
	Issuer           string `json:"issuer"`
}

type TOTPObject struct {
	QRCode string
	Secret string
	URI    string
}

type EnrollFactorResponse struct {
	ID        string
	CreatedAt string
	Type      string
	TOTP      TOTPObject
}

// RecoveryCodesResponse repreesnts a successful Backup code generation response
type RecoveryCodesResponse struct {
	RecoveryCodes []string
}

func (a *API) EnableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.EnableMFA(tx); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, user)
}

func (a *API) DisableMFA(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	err := a.db.Transaction(func(tx *storage.Connection) error {
		if terr := user.DisableMFA(tx); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.UserModifiedAction, r.RemoteAddr, map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"user_phone": user.Phone,
		}); terr != nil {
			return terr
		}
		return nil
	})
	if err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, user)
}

func (a *API) GenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) error {
	const NUM_RECOVERY_CODES = 8
	const RECOVERY_CODE_LENGTH = 8

	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return MFANotEnabledError
	}
	now := time.Now()
	recoveryCodeModels := []*models.RecoveryCode{}
	var terr error
	var recoveryCode string
	var recoveryCodes []string
	var recoveryCodeModel *models.RecoveryCode

	for i := 0; i < NUM_RECOVERY_CODES; i++ {
		recoveryCode = crypto.SecureToken(RECOVERY_CODE_LENGTH)
		recoveryCodeModel, terr = models.NewRecoveryCode(user, recoveryCode, &now)
		if terr != nil {
			return internalServerError("Error creating backup code").WithInternalError(terr)
		}
		recoveryCodes = append(recoveryCodes, recoveryCode)
		recoveryCodeModels = append(recoveryCodeModels, recoveryCodeModel)
	}
	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(recoveryCodeModels); terr != nil {
			return terr
		}

		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.GenerateRecoveryCodesAction, r.RemoteAddr, nil); terr != nil {
			return terr
		}
		return nil
	})

	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		RecoveryCodes: recoveryCodes,
	})
}

func (a *API) EnrollFactor(w http.ResponseWriter, r *http.Request) error {
	const FACTOR_PREFIX = "factor"
	const IMAGE_SIDE_LENGTH = 300
	ctx := r.Context()
	user := getUser(ctx)
	instanceID := getInstanceID(ctx)
	if !user.MFAEnabled {
		return MFANotEnabledError
	}

	params := &EnrollFactorParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		return badRequestError("Could not read EnrollFactor params: %v", err)
	}

	if (params.FactorType != "totp") && (params.FactorType != "webauthn") {
		return unprocessableEntityError("FactorType needs to be either 'totp' or 'webauthn'")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      params.Issuer,
		AccountName: params.Issuer,
	})

	if err != nil {
		return internalServerError("Error generating QR Code secret key").WithInternalError(err)
	}
	var buf bytes.Buffer

	// Test with QRCode Encode
	img, err := key.Image(IMAGE_SIDE_LENGTH, IMAGE_SIDE_LENGTH)
	png.Encode(&buf, img)
	if err != nil {
		return internalServerError("Error generating QR Code image").WithInternalError(err)
	}
	qrAsBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	factorID := fmt.Sprintf("%s_%s", FACTOR_PREFIX, crypto.SecureToken())

	factor, terr := models.NewFactor(user, params.FactorSimpleName, factorID, params.FactorType, key.Secret())
	if terr != nil {
		return internalServerError("Database error creating factor").WithInternalError(err)
	}

	terr = a.db.Transaction(func(tx *storage.Connection) error {
		if terr = tx.Create(factor); terr != nil {
			return terr
		}
		if terr := models.NewAuditLogEntry(tx, instanceID, user, models.EnrollFactorAction, r.RemoteAddr, nil); terr != nil {
			return terr
		}

		return nil
	})

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:   factor.ID,
		Type: factor.FactorType,
		TOTP: TOTPObject{
			QRCode: fmt.Sprintf("data:img/png;base64,%v", qrAsBase64),
			Secret: factor.SecretKey,
			URI:    key.URL(),
		},
	})
}
