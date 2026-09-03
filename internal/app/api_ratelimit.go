package app

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// rateLimiter is a fixed-window counter keyed by caller identity. It exists to
// blunt bulk extraction: a credential that is valid for one secret should not
// be able to drain the database in a loop before anyone reads the audit log.
type rateLimiter struct {
	mutex   sync.Mutex
	limit   int
	window  time.Duration
	windows map[string]*rateWindow
	now     func() time.Time
}

type rateWindow struct {
	count     int
	expiresAt time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		window:  window,
		windows: make(map[string]*rateWindow),
		now:     time.Now,
	}
}

// allow records an attempt and reports whether it is within the limit. When it
// is not, it returns how long the caller should wait.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := l.now()
	current, ok := l.windows[key]
	if !ok || now.After(current.expiresAt) {
		l.windows[key] = &rateWindow{count: 1, expiresAt: now.Add(l.window)}
		l.sweep(now)
		return true, 0
	}
	if current.count >= l.limit {
		return false, current.expiresAt.Sub(now)
	}
	current.count++
	return true, 0
}

// sweep drops expired windows so the map does not grow without bound. It runs
// under the caller's lock, on the cheap path where a window was just created.
func (l *rateLimiter) sweep(now time.Time) {
	if len(l.windows) < 1024 {
		return
	}
	for key, window := range l.windows {
		if now.After(window.expiresAt) {
			delete(l.windows, key)
		}
	}
}

// rateLimitKey identifies the caller for limiting purposes. A token is limited
// as itself; a session user as themselves.
func rateLimitKey(principal *Principal, r *http.Request) string {
	if principal.TokenID > 0 {
		return "token:" + strconv.Itoa(principal.TokenID)
	}
	if principal.Username != "" {
		return "user:" + principal.Username
	}
	return "ip:" + clientIP(r)
}

// limitReveal wraps a handler that returns plaintext, so bulk extraction is
// slowed and visible rather than silent.
func (s *Server) limitReveal(next apiHandler) apiHandler {
	return func(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
		allowed, retryAfter := s.revealLimiter.allow(rateLimitKey(principal, r))
		if !allowed {
			seconds := int(retryAfter.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			s.logger.Printf("api: reveal rate limit hit by %s", principal.Actor())
			writeAPIError(w, http.StatusTooManyRequests, "rate_limited",
				"Too many secret reads. Wait and try again.",
				map[string]any{"retry_after_seconds": seconds})
			return
		}
		next(w, r, values, principal)
	}
}
