package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypt-server/internal/store"
)

type escrowRequest struct {
	Serial       string `json:"serial"`
	Username     string `json:"username"`
	ComputerName string `json:"computer_name"`
	SecretType   string `json:"secret_type"`
	Secret       string `json:"secret"`
	Platform     string `json:"platform"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
	HardwareUUID string `json:"hardware_uuid"`
}

type escrowResponse struct {
	ComputerID        int    `json:"computer_id"`
	Serial            string `json:"serial"`
	Username          string `json:"username"`
	SecretID          int    `json:"secret_id"`
	SecretType        string `json:"secret_type"`
	NewSecretEscrowed bool   `json:"new_secret_escrowed"`
	RotationRequired  bool   `json:"rotation_required"`
}

// handleAPIEscrow is the JSON form of /checkin/. The legacy form-encoded route
// stays in place; both write through the same store calls.
func (s *Server) handleAPIEscrow(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body escrowRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	serial := strings.TrimSpace(body.Serial)
	if serial == "" {
		writeAPIError(w, http.StatusBadRequest, "serial_required", "A serial is required.", nil)
		return
	}
	secretValue := strings.TrimSpace(body.Secret)
	if secretValue == "" {
		writeAPIError(w, http.StatusBadRequest, "secret_required", "A secret is required.", nil)
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" {
		writeAPIError(w, http.StatusBadRequest, "username_required", "A username is required.", nil)
		return
	}
	computerName := strings.TrimSpace(body.ComputerName)
	if computerName == "" {
		computerName = serial
	}
	secretType := strings.TrimSpace(body.SecretType)
	if secretType == "" {
		secretType = "recovery_key"
	}

	computer, err := s.store.UpsertComputer(serial, username, computerName, time.Now())
	if err != nil {
		s.logger.Printf("api: escrow upsert computer failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	if body.Platform != "" || body.OSVersion != "" || body.AgentVersion != "" || body.HardwareUUID != "" {
		if err := s.store.UpdateComputerMetadata(computer.ID,
			strings.TrimSpace(body.Platform),
			strings.TrimSpace(body.OSVersion),
			strings.TrimSpace(body.AgentVersion),
			strings.TrimSpace(body.HardwareUUID),
		); err != nil {
			s.logger.Printf("api: escrow metadata update failed: %v", err)
		}
	}

	secret, isNew, err := s.store.AddSecret(computer.ID, secretType, secretValue, false)
	if err != nil {
		s.logger.Printf("api: escrow add secret failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	action := EventSecretUpdated
	if isNew {
		action = EventSecretEscrowed
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     action,
		TargetType: "secret",
		TargetID:   strconv.Itoa(secret.ID),
		Metadata: map[string]any{
			"serial":      computer.Serial,
			"secret_type": secret.SecretType,
			"platform":    strings.TrimSpace(body.Platform),
		},
	})

	writeAPIJSON(w, http.StatusCreated, escrowResponse{
		ComputerID:        computer.ID,
		Serial:            computer.Serial,
		Username:          computer.Username,
		SecretID:          secret.ID,
		SecretType:        secret.SecretType,
		NewSecretEscrowed: isNew,
		RotationRequired:  secret.RotationRequired,
	})
}

type escrowStatusResponse struct {
	Serial           string  `json:"serial"`
	SecretType       string  `json:"secret_type"`
	Escrowed         bool    `json:"escrowed"`
	DateEscrowed     *string `json:"date_escrowed"`
	RotationRequired bool    `json:"rotation_required"`
}

// handleAPIEscrowStatus is the JSON form of /verify/<serial>/<type>/.
func (s *Server) handleAPIEscrowStatus(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	if serial == "" {
		writeAPIError(w, http.StatusBadRequest, "serial_required", "A serial is required.", nil)
		return
	}
	secretType := strings.TrimSpace(r.URL.Query().Get("secret_type"))
	if secretType == "" {
		secretType = "recovery_key"
	}

	response := escrowStatusResponse{Serial: serial, SecretType: secretType}
	computer, err := s.store.GetComputerBySerial(serial)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIJSON(w, http.StatusOK, response)
			return
		}
		s.logger.Printf("api: escrow status computer lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	secret, err := s.store.GetLatestSecretByComputerAndType(computer.ID, secretType)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIJSON(w, http.StatusOK, response)
			return
		}
		s.logger.Printf("api: escrow status secret lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	response.Serial = computer.Serial
	response.Escrowed = true
	response.DateEscrowed = formatTime(secret.DateEscrowed)
	response.RotationRequired = secret.RotationRequired
	writeAPIJSON(w, http.StatusOK, response)
}

type rotationCompleteRequest struct {
	Serial     string `json:"serial"`
	SecretType string `json:"secret_type"`
}

// handleAPIRotationComplete lets a client acknowledge that it rotated the key
// it was asked to rotate, clearing the flag the server set on retrieval.
func (s *Server) handleAPIRotationComplete(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body rotationCompleteRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	serial := strings.TrimSpace(body.Serial)
	if serial == "" {
		writeAPIError(w, http.StatusBadRequest, "serial_required", "A serial is required.", nil)
		return
	}
	secretType := strings.TrimSpace(body.SecretType)
	if secretType == "" {
		secretType = "recovery_key"
	}
	computer, err := s.store.GetComputerBySerial(serial)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	secret, err := s.store.GetLatestSecretByComputerAndType(computer.ID, secretType)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "secret_not_found", "No secret of that type is escrowed for this computer.", nil)
			return
		}
		s.logger.Printf("api: rotation complete lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	updated, err := s.store.SetSecretRotationRequired(secret.ID, false)
	if err != nil {
		s.logger.Printf("api: rotation complete update failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventSecretRotationFlagged,
		TargetType: "secret",
		TargetID:   strconv.Itoa(updated.ID),
		Metadata: map[string]any{
			"serial":            computer.Serial,
			"secret_type":       updated.SecretType,
			"rotation_required": false,
			"acknowledged":      true,
		},
	})
	writeAPIJSON(w, http.StatusOK, newSecretView(updated))
}
