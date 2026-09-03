package store

import "time"

// DateTimeFormat is the standard format for displaying dates (matches Django's Y-m-d H:i:s).
const DateTimeFormat = "2006-01-02 15:04:05"

type Computer struct {
	ID           int
	Serial       string
	Username     string
	ComputerName string
	LastCheckin  time.Time
	Platform     string
	OSVersion    string
	AgentVersion string
	HardwareUUID string
}

// LastCheckinFormatted returns the last checkin time in display format.
func (c Computer) LastCheckinFormatted() string {
	return c.LastCheckin.Format(DateTimeFormat)
}

type Secret struct {
	ID               int
	ComputerID       int
	SecretType       string
	Secret           string
	DateEscrowed     time.Time
	RotationRequired bool
}

// SecretTypeDisplay returns the human-readable display name for the secret type.
func (s Secret) SecretTypeDisplay() string {
	switch s.SecretType {
	case "recovery_key":
		return "Recovery Key"
	case "password":
		return "Password"
	case "unlock_pin":
		return "Unlock PIN"
	default:
		return s.SecretType
	}
}

// DateEscrowedFormatted returns the escrow date in display format.
func (s Secret) DateEscrowedFormatted() string {
	return s.DateEscrowed.Format(DateTimeFormat)
}

type Request struct {
	ID                int
	SecretID          int
	RequestingUser    string
	Approved          *bool
	AuthUser          string
	ReasonForRequest  string
	ReasonForApproval string
	DateRequested     time.Time
	DateApproved      *time.Time
	Current           bool
}

// DateRequestedFormatted returns the request date in display format.
func (r Request) DateRequestedFormatted() string {
	return r.DateRequested.Format(DateTimeFormat)
}

// DateApprovedFormatted returns the approval date in display format, or empty string if not approved.
func (r Request) DateApprovedFormatted() string {
	if r.DateApproved == nil {
		return ""
	}
	return r.DateApproved.Format(DateTimeFormat)
}

type User struct {
	ID                int
	Username          string
	PasswordHash      string
	IsStaff           bool
	CanApprove        bool
	LocalLoginEnabled bool
	MustResetPassword bool
	AuthSource        string
}

type AuditEvent struct {
	ID         int
	Actor      string
	TargetUser string
	Action     string
	Reason     string
	IPAddress  string
	CreatedAt  time.Time
	TargetType string
	TargetID   string
	Metadata   string
}

// CreatedAtFormatted returns the created time in display format.
func (a AuditEvent) CreatedAtFormatted() string {
	return a.CreatedAt.Format(DateTimeFormat)
}

// APIToken is a credential used by devices, services or users to call the
// JSON API. Only the hash of the token is ever persisted.
type APIToken struct {
	ID         int
	Name       string
	Prefix     string
	TokenHash  string
	Kind       string
	Scopes     []string
	Username   string
	CreatedBy  string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	LastUsedIP string
	RevokedAt  *time.Time
}

// Active reports whether the token may still be used at the given time.
func (t APIToken) Active(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return false
	}
	return true
}

// HasScope reports whether the token carries the named scope. The admin scope
// implies every other scope.
func (t APIToken) HasScope(scope string) bool {
	for _, granted := range t.Scopes {
		if granted == scope || granted == ScopeAdmin {
			return true
		}
	}
	return false
}

// Webhook is an outbound subscription to server events.
type Webhook struct {
	ID        int
	URL       string
	Events    []string
	Secret    string
	Active    bool
	CreatedBy string
	CreatedAt time.Time
}

// Subscribed reports whether the webhook wants the named event.
func (w Webhook) Subscribed(event string) bool {
	if !w.Active {
		return false
	}
	for _, want := range w.Events {
		if want == event || want == "*" {
			return true
		}
	}
	return false
}

// WebhookDelivery records one attempt to deliver an event.
type WebhookDelivery struct {
	ID          int
	WebhookID   int
	Event       string
	Payload     string
	StatusCode  int
	Error       string
	Attempts    int
	DeliveredAt time.Time
}

// Stats is the fleet summary returned by the API.
type Stats struct {
	ComputersTotal   int            `json:"computers_total"`
	EscrowedByType   map[string]int `json:"escrowed_by_type"`
	CheckedIn24h     int            `json:"checked_in_24h"`
	CheckedIn7d      int            `json:"checked_in_7d"`
	CheckedIn30d     int            `json:"checked_in_30d"`
	Stale            int            `json:"stale"`
	NeverEscrowed    int            `json:"never_escrowed"`
	PendingRequests  int            `json:"pending_requests"`
	RotationsPending int            `json:"rotations_pending"`
	SecretsTotal     int            `json:"secrets_total"`
	UsersTotal       int            `json:"users_total"`
}
