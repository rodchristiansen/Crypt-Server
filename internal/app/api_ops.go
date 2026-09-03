package app

import (
	"net/http"
	"time"
)

// handleAPICleanupRequests runs the retention sweep on demand. The same sweep
// runs on a timer; this endpoint exists so an operator can force it after
// changing the retention window.
func (s *Server) handleAPICleanupRequests(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	cutoff := time.Now().Add(-s.requestRetention())
	cleaned, err := s.store.CleanupRequests(cutoff)
	if err != nil {
		s.logger.Printf("api: cleanup requests failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     "maintenance.cleanup_requests",
		TargetType: "maintenance",
		Metadata: map[string]any{
			"cleaned": cleaned,
			"cutoff":  cutoff.UTC().Format(time.RFC3339),
		},
	})
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"cleaned": cleaned,
		"cutoff":  cutoff.UTC().Format(time.RFC3339),
	})
}
