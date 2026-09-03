package app

import (
	"net/http"
	"strconv"
	"strings"

	"crypt-server/internal/store"
)

func (s *Server) resolveRequest(w http.ResponseWriter, values pathValues) (*store.Request, bool) {
	id, err := strconv.Atoi(values["id"])
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "request_not_found", "No request with that id.", nil)
		return nil, false
	}
	request, err := s.store.GetRequestByID(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "request_not_found", "No request with that id.", nil)
			return nil, false
		}
		s.logger.Printf("api: request lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return nil, false
	}
	return request, true
}

// principalCanApprove applies the same policy the HTML approval screen does:
// the caller must hold the approve scope, and unless APPROVE_OWN is set they
// may not approve a request they raised themselves.
func (s *Server) principalCanApprove(principal *Principal, request *store.Request) bool {
	if !principal.Has(store.ScopeRequestsApprove) {
		return false
	}
	if !s.settings.ApproveOwn && principal.Username != "" && principal.Username == request.RequestingUser {
		return false
	}
	return true
}

type createRequestBody struct {
	SecretID int    `json:"secret_id"`
	Reason   string `json:"reason"`
}

func (s *Server) handleAPICreateRequest(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body createRequestBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if body.SecretID <= 0 {
		writeAPIError(w, http.StatusBadRequest, "secret_id_required", "A secret_id is required.", nil)
		return
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		writeAPIError(w, http.StatusBadRequest, "reason_required", "A reason for the request is required.", nil)
		return
	}
	if principal.Username == "" {
		writeAPIError(w, http.StatusForbidden, "user_required",
			"Only a signed-in user or a personal access token can raise a request.", nil)
		return
	}
	secret, err := s.store.GetSecretByID(body.SecretID)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "secret_not_found", "No secret with that id.", nil)
			return
		}
		s.logger.Printf("api: create request secret lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	// A user who may approve, in an estate that allows self-approval, has
	// their request approved on creation, exactly as the web UI does.
	var approved *bool
	approver := ""
	if principal.CanApprove && s.settings.ApproveOwn {
		approvedValue := true
		approved = &approvedValue
		approver = principal.Username
	}
	request, err := s.store.AddRequest(secret.ID, principal.Username, reason, approver, approved)
	if err != nil {
		s.logger.Printf("api: create request failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	action := EventRequestCreated
	if approved != nil {
		action = EventRequestApproved
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     action,
		TargetType: "request",
		TargetID:   strconv.Itoa(request.ID),
		TargetUser: request.RequestingUser,
		Reason:     reason,
		Metadata: map[string]any{
			"secret_id":     secret.ID,
			"secret_type":   secret.SecretType,
			"self_approved": approved != nil,
		},
	})
	writeAPIJSON(w, http.StatusCreated, newRequestView(request))
}

func (s *Server) handleAPIListRequests(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	query := r.URL.Query()
	filter := store.RequestFilter{
		Status:         strings.TrimSpace(query.Get("status")),
		SecretID:       queryInt(r, "secret_id", 0),
		ComputerSerial: strings.TrimSpace(query.Get("computer_serial")),
		RequestingUser: strings.TrimSpace(query.Get("requesting_user")),
	}
	if mine := queryBool(r, "mine"); mine != nil && *mine {
		filter.RequestingUser = principal.Username
	}
	if current := queryBool(r, "current"); current != nil {
		filter.CurrentOnly = *current
	}
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountRequestsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count requests failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	requests, err := s.store.ListRequestsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list requests failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]requestView, 0, len(requests))
	for _, request := range requests {
		view := newRequestView(request)
		canApprove := s.principalCanApprove(principal, request)
		view.CanApprove = &canApprove
		results = append(results, view)
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

func (s *Server) handleAPIGetRequest(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	request, ok := s.resolveRequest(w, values)
	if !ok {
		return
	}
	view := newRequestView(request)
	canApprove := s.principalCanApprove(principal, request)
	view.CanApprove = &canApprove
	writeAPIJSON(w, http.StatusOK, view)
}

type decisionBody struct {
	Reason string `json:"reason"`
}

// decide is the shared body of approve and deny.
func (s *Server) decide(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal, approve bool) {
	request, ok := s.resolveRequest(w, values)
	if !ok {
		return
	}
	if request.Approved != nil {
		writeAPIError(w, http.StatusConflict, "request_already_decided",
			"This request has already been decided.",
			map[string]any{"status": requestStatus(request)})
		return
	}
	if !s.principalCanApprove(principal, request) {
		writeAPIError(w, http.StatusForbidden, "cannot_approve",
			"You may not decide this request. Self-approval is disabled on this server.", nil)
		return
	}
	var body decisionBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	reason := strings.TrimSpace(body.Reason)

	updated, err := s.store.ApproveRequest(request.ID, approve, reason, principal.Username)
	if err != nil {
		s.logger.Printf("api: decide request failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	action := EventRequestDenied
	if approve {
		action = EventRequestApproved
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     action,
		TargetType: "request",
		TargetID:   strconv.Itoa(updated.ID),
		TargetUser: updated.RequestingUser,
		Reason:     reason,
		Metadata:   map[string]any{"secret_id": updated.SecretID},
	})
	writeAPIJSON(w, http.StatusOK, newRequestView(updated))
}

func (s *Server) handleAPIApproveRequest(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	s.decide(w, r, values, principal, true)
}

func (s *Server) handleAPIDenyRequest(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	s.decide(w, r, values, principal, false)
}

func (s *Server) handleAPICancelRequest(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	request, ok := s.resolveRequest(w, values)
	if !ok {
		return
	}
	if request.Approved != nil {
		writeAPIError(w, http.StatusConflict, "request_already_decided",
			"A decided request cannot be cancelled.",
			map[string]any{"status": requestStatus(request)})
		return
	}
	if request.RequestingUser != principal.Username && !principal.Has(store.ScopeAdmin) {
		writeAPIError(w, http.StatusForbidden, "not_your_request",
			"Only the requester, or an admin, can cancel a request.", nil)
		return
	}
	if err := s.store.CancelRequest(request.ID); err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusConflict, "request_already_decided",
				"A decided request cannot be cancelled.", nil)
			return
		}
		s.logger.Printf("api: cancel request failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventRequestCancelled,
		TargetType: "request",
		TargetID:   strconv.Itoa(request.ID),
		TargetUser: request.RequestingUser,
		Metadata:   map[string]any{"secret_id": request.SecretID},
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}

type retrieveResponse struct {
	RequestID        int    `json:"request_id"`
	SecretID         int    `json:"secret_id"`
	ComputerID       int    `json:"computer_id"`
	ComputerSerial   string `json:"computer_serial"`
	ComputerName     string `json:"computer_name"`
	SecretType       string `json:"secret_type"`
	Secret           string `json:"secret"`
	DateEscrowed     string `json:"date_escrowed"`
	RotationRequired bool   `json:"rotation_required"`
}

// handleAPIRetrieveRequest returns the secret behind an approved request. This
// is the JSON form of /retrieve/ and the normal way a person reads a secret.
func (s *Server) handleAPIRetrieveRequest(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	request, ok := s.resolveRequest(w, values)
	if !ok {
		return
	}
	if request.Approved == nil || !*request.Approved {
		writeAPIError(w, http.StatusForbidden, "request_not_approved",
			"This request has not been approved.",
			map[string]any{"status": requestStatus(request)})
		return
	}
	if !request.Current {
		writeAPIError(w, http.StatusForbidden, "request_expired",
			"This approval has expired. Raise a new request.", nil)
		return
	}
	if request.RequestingUser != principal.Username && !principal.Has(store.ScopeRequestsApprove) {
		writeAPIError(w, http.StatusForbidden, "not_your_request",
			"Only the requester, or an approver, can retrieve this secret.", nil)
		return
	}

	secret, err := s.store.GetSecretByID(request.SecretID)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "secret_not_found", "The secret behind this request is gone.", nil)
			return
		}
		s.logger.Printf("api: retrieve secret lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	computer, err := s.store.GetComputerByID(secret.ComputerID)
	if err != nil {
		s.logger.Printf("api: retrieve computer lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	s.recordEvent(r, principal, eventRecord{
		Action:     EventSecretViewed,
		TargetType: "secret",
		TargetID:   strconv.Itoa(secret.ID),
		TargetUser: request.RequestingUser,
		Reason:     request.ReasonForRequest,
		Metadata: map[string]any{
			"serial":      computer.Serial,
			"secret_type": secret.SecretType,
			"request_id":  request.ID,
			"break_glass": false,
		},
	})

	rotationRequired := secret.RotationRequired
	if s.settings.RotateViewedSecrets {
		if updated, err := s.store.SetSecretRotationRequired(secret.ID, true); err != nil {
			s.logger.Printf("api: flag rotation after retrieve failed: %v", err)
		} else {
			rotationRequired = updated.RotationRequired
		}
	}

	writeAPIJSON(w, http.StatusOK, retrieveResponse{
		RequestID:        request.ID,
		SecretID:         secret.ID,
		ComputerID:       computer.ID,
		ComputerSerial:   computer.Serial,
		ComputerName:     computer.ComputerName,
		SecretType:       secret.SecretType,
		Secret:           secret.Secret,
		DateEscrowed:     *formatTime(secret.DateEscrowed),
		RotationRequired: rotationRequired,
	})
}
