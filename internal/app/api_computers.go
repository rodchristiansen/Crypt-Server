package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypt-server/internal/store"
)

// resolveComputer looks up a computer from a path value that is either a
// numeric id or, under /by-serial/, a serial number.
func (s *Server) resolveComputer(values pathValues) (*store.Computer, error) {
	if serial, ok := values["serial"]; ok {
		return s.store.GetComputerBySerial(serial)
	}
	id, err := strconv.Atoi(values["id"])
	if err != nil {
		return nil, store.ErrNotFound
	}
	return s.store.GetComputerByID(id)
}

// writeComputerLookupError turns a store lookup failure into an API response.
func (s *Server) writeComputerLookupError(w http.ResponseWriter, err error) {
	if err == store.ErrNotFound {
		writeAPIError(w, http.StatusNotFound, "computer_not_found", "No computer with that identifier.", nil)
		return
	}
	s.logger.Printf("api: computer lookup failed: %v", err)
	writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
}

// computerFilterFrom builds a store filter from the query string.
func computerFilterFrom(r *http.Request) store.ComputerFilter {
	query := r.URL.Query()
	filter := store.ComputerFilter{
		Search:           strings.TrimSpace(query.Get("search")),
		Username:         strings.TrimSpace(query.Get("username")),
		Platform:         strings.TrimSpace(query.Get("platform")),
		SecretType:       strings.TrimSpace(query.Get("secret_type")),
		Escrowed:         queryBool(r, "escrowed"),
		RotationRequired: queryBool(r, "rotation_required"),
		CheckedInBefore:  queryTime(r, "last_checkin_before"),
		CheckedInAfter:   queryTime(r, "last_checkin_after"),
		Sort:             strings.TrimSpace(query.Get("sort")),
	}
	if days := queryInt(r, "stale_days", 0); days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		filter.CheckedInBefore = &cutoff
	}
	return filter
}

func (s *Server) handleAPIListComputers(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	filter := computerFilterFrom(r)
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountComputersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count computers failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	computers, err := s.store.ListComputersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list computers failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	results := make([]computerView, 0, len(computers))
	for _, computer := range computers {
		view := newComputerView(computer)
		if secretCount, err := s.store.CountSecretsFiltered(store.SecretFilter{ComputerID: computer.ID}); err == nil {
			view.SecretsCount = &secretCount
		}
		results = append(results, view)
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

func (s *Server) handleAPIExportComputersCSV(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	filter := computerFilterFrom(r)
	computers, err := s.store.ListComputersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: export computers failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	rows := make([][]string, 0, len(computers))
	for _, computer := range computers {
		lastCheckin := ""
		if formatted := formatTime(computer.LastCheckin); formatted != nil {
			lastCheckin = *formatted
		}
		secretCount, _ := s.store.CountSecretsFiltered(store.SecretFilter{ComputerID: computer.ID})
		rows = append(rows, []string{
			strconv.Itoa(computer.ID),
			computer.Serial,
			computer.ComputerName,
			computer.Username,
			lastCheckin,
			computer.Platform,
			computer.OSVersion,
			computer.AgentVersion,
			strconv.Itoa(secretCount),
		})
	}
	writeCSV(w, "computers.csv",
		[]string{"id", "serial", "computer_name", "username", "last_checkin", "platform", "os_version", "agent_version", "secrets_count"},
		rows)
}

func (s *Server) handleAPIStaleComputers(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	days := queryInt(r, "days", int(s.settings.StaleAfter.Hours()/24))
	if days <= 0 {
		days = 30
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	filter := store.ComputerFilter{CheckedInBefore: &cutoff, Sort: "last_checkin"}
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountComputersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count stale computers failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	computers, err := s.store.ListComputersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list stale computers failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]computerView, 0, len(computers))
	for _, computer := range computers {
		results = append(results, newComputerView(computer))
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

type createComputerRequest struct {
	Serial       string `json:"serial"`
	Username     string `json:"username"`
	ComputerName string `json:"computer_name"`
}

func (s *Server) handleAPICreateComputer(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body createComputerRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	serial := strings.TrimSpace(body.Serial)
	if serial == "" {
		writeAPIError(w, http.StatusBadRequest, "serial_required", "A serial is required.", nil)
		return
	}
	if existing, err := s.store.GetComputerBySerial(serial); err == nil {
		writeAPIError(w, http.StatusConflict, "computer_exists",
			"A computer with that serial already exists.",
			map[string]any{"computer_id": existing.ID})
		return
	} else if err != store.ErrNotFound {
		s.logger.Printf("api: check computer serial failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	computerName := strings.TrimSpace(body.ComputerName)
	if computerName == "" {
		computerName = serial
	}
	computer, err := s.store.AddComputer(serial, strings.TrimSpace(body.Username), computerName)
	if err != nil {
		s.logger.Printf("api: create computer failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventComputerCreated,
		TargetType: "computer",
		TargetID:   strconv.Itoa(computer.ID),
		Metadata:   map[string]any{"serial": computer.Serial},
	})
	writeAPIJSON(w, http.StatusCreated, newComputerView(computer))
}

func (s *Server) handleAPIGetComputer(w http.ResponseWriter, r *http.Request, values pathValues, _ *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	view := newComputerView(computer)

	secrets, err := s.store.ListSecretsByComputer(computer.ID)
	if err != nil {
		s.logger.Printf("api: list computer secrets failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	view.Secrets = make([]secretView, 0, len(secrets))
	for _, secret := range secrets {
		view.Secrets = append(view.Secrets, newSecretView(secret))
	}
	secretCount := len(secrets)
	view.SecretsCount = &secretCount

	if pending, err := s.store.PendingRequestIDsForComputer(computer.ID); err == nil {
		count := len(pending)
		view.PendingRequestCount = &count
	}
	writeAPIJSON(w, http.StatusOK, view)
}

type patchComputerRequest struct {
	Username     *string `json:"username"`
	ComputerName *string `json:"computer_name"`
}

func (s *Server) handleAPIPatchComputer(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	var body patchComputerRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	username := computer.Username
	if body.Username != nil {
		username = strings.TrimSpace(*body.Username)
	}
	computerName := computer.ComputerName
	if body.ComputerName != nil {
		computerName = strings.TrimSpace(*body.ComputerName)
	}
	if computerName == "" {
		writeAPIError(w, http.StatusBadRequest, "computer_name_required", "A computer name is required.", nil)
		return
	}

	updated, err := s.store.UpdateComputer(computer.ID, username, computerName)
	if err != nil {
		s.logger.Printf("api: update computer failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventComputerUpdated,
		TargetType: "computer",
		TargetID:   strconv.Itoa(updated.ID),
		Metadata: map[string]any{
			"serial":        updated.Serial,
			"username":      updated.Username,
			"computer_name": updated.ComputerName,
		},
	})
	writeAPIJSON(w, http.StatusOK, newComputerView(updated))
}

func (s *Server) handleAPIDeleteComputer(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	force := queryBool(r, "force")
	pending, err := s.store.PendingRequestIDsForComputer(computer.ID)
	if err != nil {
		s.logger.Printf("api: pending requests lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	if len(pending) > 0 && (force == nil || !*force) {
		writeAPIError(w, http.StatusConflict, "pending_requests_exist",
			"This computer has pending retrieval requests. Resolve them, or repeat with force=true.",
			map[string]any{"pending_requests": pending})
		return
	}
	if err := s.store.DeleteComputer(computer.ID); err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "computer_not_found", "No computer with that identifier.", nil)
			return
		}
		s.logger.Printf("api: delete computer failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventComputerDeleted,
		TargetType: "computer",
		TargetID:   strconv.Itoa(computer.ID),
		Metadata: map[string]any{
			"serial":          computer.Serial,
			"forced":          force != nil && *force,
			"pending_removed": len(pending),
		},
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}

type bulkDeleteRequest struct {
	Serials []string `json:"serials"`
	Force   bool     `json:"force"`
}

type bulkDeleteResult struct {
	Serial string `json:"serial"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func (s *Server) handleAPIBulkDeleteComputers(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body bulkDeleteRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if len(body.Serials) == 0 {
		writeAPIError(w, http.StatusBadRequest, "serials_required", "Provide at least one serial.", nil)
		return
	}
	results := make([]bulkDeleteResult, 0, len(body.Serials))
	for _, rawSerial := range body.Serials {
		serial := strings.TrimSpace(rawSerial)
		computer, err := s.store.GetComputerBySerial(serial)
		if err != nil {
			results = append(results, bulkDeleteResult{Serial: serial, Status: "not_found"})
			continue
		}
		pending, err := s.store.PendingRequestIDsForComputer(computer.ID)
		if err != nil {
			results = append(results, bulkDeleteResult{Serial: serial, Status: "error", Detail: "lookup failed"})
			continue
		}
		if len(pending) > 0 && !body.Force {
			results = append(results, bulkDeleteResult{
				Serial: serial,
				Status: "skipped",
				Detail: "pending retrieval requests exist",
			})
			continue
		}
		if err := s.store.DeleteComputer(computer.ID); err != nil {
			results = append(results, bulkDeleteResult{Serial: serial, Status: "error", Detail: "delete failed"})
			continue
		}
		s.recordEvent(r, principal, eventRecord{
			Action:     EventComputerDeleted,
			TargetType: "computer",
			TargetID:   strconv.Itoa(computer.ID),
			Metadata:   map[string]any{"serial": computer.Serial, "bulk": true, "forced": body.Force},
		})
		results = append(results, bulkDeleteResult{Serial: serial, Status: "deleted"})
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleAPIComputerSecrets(w http.ResponseWriter, r *http.Request, values pathValues, _ *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	secrets, err := s.store.ListSecretsByComputer(computer.ID)
	if err != nil {
		s.logger.Printf("api: list computer secrets failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]secretView, 0, len(secrets))
	for _, secret := range secrets {
		results = append(results, newSecretView(secret))
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"computer_id":     computer.ID,
		"computer_serial": computer.Serial,
		"secrets":         results,
	})
}

type addSecretRequest struct {
	SecretType       string `json:"secret_type"`
	Secret           string `json:"secret"`
	RotationRequired bool   `json:"rotation_required"`
}

func (s *Server) handleAPIAddComputerSecret(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	var body addSecretRequest
	if !decodeJSONBody(w, r, &body) {
		return
	}
	secretValue := strings.TrimSpace(body.Secret)
	if secretValue == "" {
		writeAPIError(w, http.StatusBadRequest, "secret_required", "A secret value is required.", nil)
		return
	}
	secretType := strings.TrimSpace(body.SecretType)
	if secretType == "" {
		secretType = "recovery_key"
	}
	secret, isNew, err := s.store.AddSecret(computer.ID, secretType, secretValue, body.RotationRequired)
	if err != nil {
		s.logger.Printf("api: add secret failed: %v", err)
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
			"manual":      true,
		},
	})
	writeAPIJSON(w, http.StatusCreated, newSecretView(secret))
}

func (s *Server) handleAPIComputerRequests(w http.ResponseWriter, r *http.Request, values pathValues, _ *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	filter := store.RequestFilter{ComputerSerial: computer.Serial}
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountRequestsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count computer requests failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	requests, err := s.store.ListRequestsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list computer requests failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]requestView, 0, len(requests))
	for _, request := range requests {
		results = append(results, newRequestView(request))
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

func (s *Server) handleAPIComputerAudit(w http.ResponseWriter, r *http.Request, values pathValues, _ *Principal) {
	computer, err := s.resolveComputer(values)
	if err != nil {
		s.writeComputerLookupError(w, err)
		return
	}
	filter := store.AuditFilter{TargetType: "computer", TargetID: strconv.Itoa(computer.ID)}
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	events, err := s.store.ListAuditEventsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: computer audit failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	count, err := s.store.CountAuditEventsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: computer audit count failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]auditView, 0, len(events))
	for _, event := range events {
		results = append(results, newAuditView(event))
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}
