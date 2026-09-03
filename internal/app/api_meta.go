package app

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypt-server/internal/store"
)

// handleAPIHealth is an unauthenticated liveness probe.
func (s *Server) handleAPIHealth(w http.ResponseWriter, _ *http.Request, _ pathValues) {
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": Version,
	})
}

// handleAPIReady checks that the store answers before reporting ready.
func (s *Server) handleAPIReady(w http.ResponseWriter, _ *http.Request, _ pathValues) {
	if _, err := s.store.CountComputersFiltered(store.ComputerFilter{}); err != nil {
		s.logger.Printf("api: readiness check failed: %v", err)
		writeAPIError(w, http.StatusServiceUnavailable, "not_ready", "The database is not reachable.", nil)
		return
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"status":  "ready",
		"version": Version,
	})
}

// handleAPISettings reports the policy flags a client needs to reason about
// the workflow it is driving.
func (s *Server) handleAPISettings(w http.ResponseWriter, _ *http.Request, _ pathValues, _ *Principal) {
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"approve_own":            s.settings.ApproveOwn,
		"all_approve":            s.settings.AllApprove,
		"rotate_viewed_secrets":  s.settings.RotateViewedSecrets,
		"request_retention_days": int(s.requestRetention().Hours() / 24),
		"stale_after_days":       int(s.settings.StaleAfter.Hours() / 24),
		"webhooks_enabled":       s.settings.WebhooksEnabled,
		"saml_enabled":           s.samlSP != nil,
		"secret_types":           []string{"recovery_key", "password", "unlock_pin"},
		"scopes":                 store.AllScopes,
		"events":                 AllEvents,
		"version":                Version,
	})
}

func (s *Server) handleAPIStats(w http.ResponseWriter, _ *http.Request, _ pathValues, _ *Principal) {
	stats, err := s.store.Stats(time.Now(), s.settings.StaleAfter)
	if err != nil {
		s.logger.Printf("api: stats failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	writeAPIJSON(w, http.StatusOK, stats)
}

// handleMetrics exposes the same figures in Prometheus text format. Escrow
// coverage is the number that matters: how much of the fleet the server could
// actually recover.
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request, _ pathValues, _ *Principal) {
	stats, err := s.store.Stats(time.Now(), s.settings.StaleAfter)
	if err != nil {
		s.logger.Printf("api: metrics failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	var builder strings.Builder
	gauge := func(name, help string, value int) {
		fmt.Fprintf(&builder, "# HELP crypt_%s %s\n", name, help)
		fmt.Fprintf(&builder, "# TYPE crypt_%s gauge\n", name)
		fmt.Fprintf(&builder, "crypt_%s %d\n", name, value)
	}
	gauge("computers_total", "Computers known to the server.", stats.ComputersTotal)
	gauge("secrets_total", "Secrets held by the server.", stats.SecretsTotal)
	gauge("computers_never_escrowed", "Computers that have never escrowed a secret.", stats.NeverEscrowed)
	gauge("computers_stale", "Computers that have not checked in recently.", stats.Stale)
	gauge("computers_checked_in_24h", "Computers that checked in within 24 hours.", stats.CheckedIn24h)
	gauge("computers_checked_in_7d", "Computers that checked in within 7 days.", stats.CheckedIn7d)
	gauge("computers_checked_in_30d", "Computers that checked in within 30 days.", stats.CheckedIn30d)
	gauge("requests_pending", "Retrieval requests awaiting a decision.", stats.PendingRequests)
	gauge("secrets_rotation_pending", "Secrets flagged for rotation.", stats.RotationsPending)
	gauge("users_total", "User accounts.", stats.UsersTotal)

	types := make([]string, 0, len(stats.EscrowedByType))
	for secretType := range stats.EscrowedByType {
		types = append(types, secretType)
	}
	sort.Strings(types)
	builder.WriteString("# HELP crypt_computers_escrowed Computers with at least one secret of each type.\n")
	builder.WriteString("# TYPE crypt_computers_escrowed gauge\n")
	for _, secretType := range types {
		fmt.Fprintf(&builder, "crypt_computers_escrowed{secret_type=%q} %d\n", secretType, stats.EscrowedByType[secretType])
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(builder.String()))
}

func auditFilterFrom(r *http.Request) store.AuditFilter {
	query := r.URL.Query()
	return store.AuditFilter{
		Search:     strings.TrimSpace(query.Get("q")),
		Actor:      strings.TrimSpace(query.Get("actor")),
		Action:     strings.TrimSpace(query.Get("action")),
		TargetUser: strings.TrimSpace(query.Get("target_user")),
		TargetType: strings.TrimSpace(query.Get("target_type")),
		From:       queryTime(r, "from"),
		To:         queryTime(r, "to"),
	}
}

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	filter := auditFilterFrom(r)
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountAuditEventsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count audit failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	events, err := s.store.ListAuditEventsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list audit failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]auditView, 0, len(events))
	for _, event := range events {
		results = append(results, newAuditView(event))
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

func (s *Server) handleAPIAuditCSV(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	filter := auditFilterFrom(r)
	filter.Limit = queryInt(r, "limit", 10000)
	events, err := s.store.ListAuditEventsFiltered(filter)
	if err != nil {
		s.logger.Printf("api: audit csv failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	rows := make([][]string, 0, len(events))
	for _, event := range events {
		rows = append(rows, []string{
			strconv.Itoa(event.ID),
			event.CreatedAt.UTC().Format(time.RFC3339),
			event.Actor,
			event.Action,
			event.TargetType,
			event.TargetID,
			event.TargetUser,
			event.Reason,
			event.IPAddress,
			event.Metadata,
		})
	}
	writeCSV(w, "audit.csv",
		[]string{"id", "created_at", "actor", "action", "target_type", "target_id", "target_user", "reason", "ip_address", "metadata"},
		rows)
}
