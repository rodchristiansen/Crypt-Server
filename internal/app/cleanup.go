package app

import "time"

const requestCleanupAfterApproval = 7 * 24 * time.Hour

func (s *Server) startRequestCleanupJob() {
	if s.settings.RequestCleanupInterval <= 0 {
		return
	}
	ticker := time.NewTicker(s.settings.RequestCleanupInterval)
	go func() {
		for range ticker.C {
			s.cleanupOldRequests()
		}
	}()
}

func (s *Server) cleanupOldRequests() {
	cutoff := time.Now().Add(-s.requestRetention())
	updated, err := s.store.CleanupRequests(cutoff)
	if err != nil {
		s.logger.Printf("cleanup requests failed: %v", err)
		return
	}
	if updated > 0 {
		s.logger.Printf("cleanup requests updated %d rows", updated)
	}
}

// requestRetention is how long an approved request stays current. It falls
// back to the historical seven days when unset.
func (s *Server) requestRetention() time.Duration {
	if s.settings.RequestRetention > 0 {
		return s.settings.RequestRetention
	}
	return requestCleanupAfterApproval
}
