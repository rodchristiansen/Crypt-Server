package app

import (
	"net/http"
	"strconv"
	"strings"

	"crypt-server/internal/store"
)

func (s *Server) resolveSecret(w http.ResponseWriter, values pathValues) (*store.Secret, bool) {
	id, err := strconv.Atoi(values["id"])
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "secret_not_found", "No secret with that id.", nil)
		return nil, false
	}
	secret, err := s.store.GetSecretByID(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "secret_not_found", "No secret with that id.", nil)
			return nil, false
		}
		s.logger.Printf("api: secret lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return nil, false
	}
	return secret, true
}

func (s *Server) handleAPIListSecrets(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	filter := store.SecretFilter{
		ComputerID:       queryInt(r, "computer_id", 0),
		SecretType:       strings.TrimSpace(r.URL.Query().Get("secret_type")),
		RotationRequired: queryBool(r, "rotation_required"),
		EscrowedBefore:   queryTime(r, "escrowed_before"),
		EscrowedAfter:    queryTime(r, "escrowed_after"),
	}
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountSecretsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count secrets failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	secrets, err := s.store.ListSecretsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list secrets failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]secretView, 0, len(secrets))
	for _, secret := range secrets {
		results = append(results, newSecretView(secret))
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

func (s *Server) handleAPIGetSecret(w http.ResponseWriter, r *http.Request, values pathValues, _ *Principal) {
	secret, ok := s.resolveSecret(w, values)
	if !ok {
		return
	}
	writeAPIJSON(w, http.StatusOK, newSecretView(secret))
}

type secretValueResponse struct {
	ID               int    `json:"id"`
	ComputerID       int    `json:"computer_id"`
	ComputerSerial   string `json:"computer_serial"`
	SecretType       string `json:"secret_type"`
	Secret           string `json:"secret"`
	DateEscrowed     string `json:"date_escrowed"`
	RotationRequired bool   `json:"rotation_required"`
	BreakGlass       bool   `json:"break_glass"`
}

// handleAPIRevealSecret is the break-glass path: it returns a secret without an
// approved request, and is gated on the secrets:reveal scope.
//
// The audit event is written before the response body, so a read is never
// served without its trail.
func (s *Server) handleAPIRevealSecret(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	secret, ok := s.resolveSecret(w, values)
	if !ok {
		return
	}
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	computer, err := s.store.GetComputerByID(secret.ComputerID)
	if err != nil {
		s.logger.Printf("api: reveal secret computer lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	s.recordEvent(r, principal, eventRecord{
		Action:     EventSecretViewed,
		TargetType: "secret",
		TargetID:   strconv.Itoa(secret.ID),
		Reason:     reason,
		Metadata: map[string]any{
			"serial":      computer.Serial,
			"secret_type": secret.SecretType,
			"break_glass": true,
		},
	})

	rotationRequired := secret.RotationRequired
	if s.settings.RotateViewedSecrets && !secret.RotationRequired {
		if updated, err := s.store.SetSecretRotationRequired(secret.ID, true); err != nil {
			s.logger.Printf("api: flag rotation after reveal failed: %v", err)
		} else {
			rotationRequired = updated.RotationRequired
		}
	}

	writeAPIJSON(w, http.StatusOK, secretValueResponse{
		ID:               secret.ID,
		ComputerID:       secret.ComputerID,
		ComputerSerial:   computer.Serial,
		SecretType:       secret.SecretType,
		Secret:           secret.Secret,
		DateEscrowed:     *formatTime(secret.DateEscrowed),
		RotationRequired: rotationRequired,
		BreakGlass:       true,
	})
}

type rotationRequest struct {
	RotationRequired bool   `json:"rotation_required"`
	Reason           string `json:"reason"`
}

func (s *Server) handleAPISetSecretRotation(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	secret, ok := s.resolveSecret(w, values)
	if !ok {
		return
	}
	var body rotationRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	updated, err := s.store.SetSecretRotationRequired(secret.ID, body.RotationRequired)
	if err != nil {
		s.logger.Printf("api: set rotation failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventSecretRotationFlagged,
		TargetType: "secret",
		TargetID:   strconv.Itoa(updated.ID),
		Reason:     strings.TrimSpace(body.Reason),
		Metadata: map[string]any{
			"secret_type":       updated.SecretType,
			"rotation_required": updated.RotationRequired,
		},
	})
	writeAPIJSON(w, http.StatusOK, newSecretView(updated))
}

func (s *Server) handleAPIDeleteSecret(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	secret, ok := s.resolveSecret(w, values)
	if !ok {
		return
	}
	if err := s.store.DeleteSecret(secret.ID); err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "secret_not_found", "No secret with that id.", nil)
			return
		}
		s.logger.Printf("api: delete secret failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventSecretDeleted,
		TargetType: "secret",
		TargetID:   strconv.Itoa(secret.ID),
		Metadata: map[string]any{
			"computer_id": secret.ComputerID,
			"secret_type": secret.SecretType,
		},
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}
