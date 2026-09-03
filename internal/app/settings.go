package app

import "time"

type Settings struct {
	ApproveOwn             bool
	AllApprove             bool
	SessionTTL             time.Duration
	CookieSecure           bool
	RequestCleanupInterval time.Duration
	RotateViewedSecrets    bool

	// APIEnabled mounts the JSON API at /api/v1/.
	APIEnabled bool
	// LegacyAPIKey is the shared key accepted on X-API-Key for escrow calls,
	// for deployments migrating from the shared-key middleware.
	LegacyAPIKey string
	// StaleAfter is how long a computer may go without checking in before it
	// counts as stale in reports.
	StaleAfter time.Duration
	// WebhooksEnabled turns outbound event delivery on.
	WebhooksEnabled bool
	// RequestRetention is how long an approved request stays current.
	RequestRetention time.Duration
	// RevealRateLimit is how many secrets one caller may read per
	// RevealRateWindow. Zero disables limiting.
	RevealRateLimit int
	// RevealRateWindow is the window RevealRateLimit applies over.
	RevealRateWindow time.Duration
}
