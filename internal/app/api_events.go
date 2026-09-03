package app

import (
	"encoding/json"
	"net/http"
	"time"

	"crypt-server/internal/store"
)

// Event names recorded in the audit log and delivered to webhooks.
const (
	EventSecretEscrowed        = "secret.escrowed"
	EventSecretUpdated         = "secret.updated"
	EventSecretViewed          = "secret.viewed"
	EventSecretDeleted         = "secret.deleted"
	EventSecretRotationFlagged = "secret.rotation_flagged"
	EventSecretsRekeyed        = "secret.rekeyed"
	EventRequestCreated        = "request.created"
	EventRequestApproved       = "request.approved"
	EventRequestDenied         = "request.denied"
	EventRequestCancelled      = "request.cancelled"
	EventComputerCreated       = "computer.created"
	EventComputerUpdated       = "computer.updated"
	EventComputerDeleted       = "computer.deleted"
	EventUserCreated           = "user.created"
	EventUserUpdated           = "user.updated"
	EventUserDeleted           = "user.deleted"
	EventUserPasswordReset     = "user.password_reset"
	EventUserSessionsRevoked   = "user.sessions_revoked"
	EventTokenCreated          = "token.created"
	EventTokenRevoked          = "token.revoked"
	EventWebhookCreated        = "webhook.created"
	EventWebhookUpdated        = "webhook.updated"
	EventWebhookDeleted        = "webhook.deleted"
)

// AllEvents lists every event a webhook may subscribe to.
var AllEvents = []string{
	EventSecretEscrowed,
	EventSecretUpdated,
	EventSecretViewed,
	EventSecretDeleted,
	EventSecretRotationFlagged,
	EventSecretsRekeyed,
	EventRequestCreated,
	EventRequestApproved,
	EventRequestDenied,
	EventRequestCancelled,
	EventComputerCreated,
	EventComputerUpdated,
	EventComputerDeleted,
	EventUserCreated,
	EventUserUpdated,
	EventUserDeleted,
	EventUserPasswordReset,
	EventUserSessionsRevoked,
	EventTokenCreated,
	EventTokenRevoked,
	EventWebhookCreated,
	EventWebhookUpdated,
	EventWebhookDeleted,
}

// IsKnownEvent reports whether the name is an event the server emits. The
// wildcard "*" subscribes to everything.
func IsKnownEvent(name string) bool {
	if name == "*" {
		return true
	}
	for _, known := range AllEvents {
		if known == name {
			return true
		}
	}
	return false
}

// eventRecord describes one thing that happened, for the audit log and any
// webhook subscribers.
type eventRecord struct {
	Action     string
	TargetType string
	TargetID   string
	TargetUser string
	Reason     string
	Metadata   map[string]any
}

// recordEvent writes an audit event and fans it out to webhook subscribers.
//
// It is called before the response body is written on every path that reveals
// a secret, so a read is never served without its audit trail.
func (s *Server) recordEvent(r *http.Request, principal *Principal, record eventRecord) {
	metadata := ""
	if len(record.Metadata) > 0 {
		if encoded, err := json.Marshal(record.Metadata); err == nil {
			metadata = string(encoded)
		}
	}
	event := store.AuditEvent{
		Actor:      principal.Actor(),
		TargetUser: record.TargetUser,
		Action:     record.Action,
		Reason:     record.Reason,
		IPAddress:  clientIP(r),
		CreatedAt:  time.Now(),
		TargetType: record.TargetType,
		TargetID:   record.TargetID,
		Metadata:   metadata,
	}
	if _, err := s.store.AddAuditEventDetailed(event); err != nil {
		s.logger.Printf("api: audit %s failed: %v", record.Action, err)
	}
	s.dispatchWebhooks(event)
}
