package app

import (
	"encoding/json"
	"time"

	"crypt-server/internal/store"
)

// computerView is the JSON shape of a computer. It never carries a secret.
type computerView struct {
	ID           int     `json:"id"`
	Serial       string  `json:"serial"`
	ComputerName string  `json:"computer_name"`
	Username     string  `json:"username"`
	LastCheckin  *string `json:"last_checkin"`
	Platform     string  `json:"platform,omitempty"`
	OSVersion    string  `json:"os_version,omitempty"`
	AgentVersion string  `json:"agent_version,omitempty"`
	HardwareUUID string  `json:"hardware_uuid,omitempty"`

	SecretsCount        *int          `json:"secrets_count,omitempty"`
	PendingRequestCount *int          `json:"pending_request_count,omitempty"`
	Secrets             []secretView  `json:"secrets,omitempty"`
	Requests            []requestView `json:"requests,omitempty"`
}

func newComputerView(computer *store.Computer) computerView {
	return computerView{
		ID:           computer.ID,
		Serial:       computer.Serial,
		ComputerName: computer.ComputerName,
		Username:     computer.Username,
		LastCheckin:  formatTime(computer.LastCheckin),
		Platform:     computer.Platform,
		OSVersion:    computer.OSVersion,
		AgentVersion: computer.AgentVersion,
		HardwareUUID: computer.HardwareUUID,
	}
}

// secretView is secret metadata. The value itself is only ever returned by the
// two reveal endpoints, in their own response shapes.
type secretView struct {
	ID               int    `json:"id"`
	ComputerID       int    `json:"computer_id"`
	SecretType       string `json:"secret_type"`
	DateEscrowed     string `json:"date_escrowed"`
	RotationRequired bool   `json:"rotation_required"`
}

func newSecretView(secret *store.Secret) secretView {
	return secretView{
		ID:               secret.ID,
		ComputerID:       secret.ComputerID,
		SecretType:       secret.SecretType,
		DateEscrowed:     secret.DateEscrowed.UTC().Format(time.RFC3339),
		RotationRequired: secret.RotationRequired,
	}
}

// requestView is one retrieval request and its decision.
type requestView struct {
	ID                int     `json:"id"`
	SecretID          int     `json:"secret_id"`
	Status            string  `json:"status"`
	RequestingUser    string  `json:"requesting_user"`
	Approved          *bool   `json:"approved"`
	AuthUser          string  `json:"auth_user,omitempty"`
	ReasonForRequest  string  `json:"reason_for_request"`
	ReasonForApproval string  `json:"reason_for_approval,omitempty"`
	DateRequested     string  `json:"date_requested"`
	DateApproved      *string `json:"date_approved"`
	Current           bool    `json:"current"`
	CanApprove        *bool   `json:"can_approve,omitempty"`
}

// requestStatus renders the tri-state approval flag as a word.
func requestStatus(request *store.Request) string {
	if request.Approved == nil {
		return "pending"
	}
	if *request.Approved {
		return "approved"
	}
	return "denied"
}

func newRequestView(request *store.Request) requestView {
	return requestView{
		ID:                request.ID,
		SecretID:          request.SecretID,
		Status:            requestStatus(request),
		RequestingUser:    request.RequestingUser,
		Approved:          request.Approved,
		AuthUser:          request.AuthUser,
		ReasonForRequest:  request.ReasonForRequest,
		ReasonForApproval: request.ReasonForApproval,
		DateRequested:     request.DateRequested.UTC().Format(time.RFC3339),
		DateApproved:      formatTimePointer(request.DateApproved),
		Current:           request.Current,
	}
}

// userView is an account. The password hash is never serialised.
type userView struct {
	ID                int    `json:"id"`
	Username          string `json:"username"`
	IsStaff           bool   `json:"is_staff"`
	CanApprove        bool   `json:"can_approve"`
	LocalLoginEnabled bool   `json:"local_login_enabled"`
	MustResetPassword bool   `json:"must_reset_password"`
	AuthSource        string `json:"auth_source"`
}

func newUserView(user *store.User) userView {
	return userView{
		ID:                user.ID,
		Username:          user.Username,
		IsStaff:           user.IsStaff,
		CanApprove:        user.CanApprove,
		LocalLoginEnabled: user.LocalLoginEnabled,
		MustResetPassword: user.MustResetPassword,
		AuthSource:        user.AuthSource,
	}
}

// tokenView is an API token's metadata. The secret is returned exactly once,
// by the creation endpoint, in its own response shape.
type tokenView struct {
	ID         int      `json:"id"`
	Name       string   `json:"name"`
	Prefix     string   `json:"prefix"`
	Kind       string   `json:"kind"`
	Scopes     []string `json:"scopes"`
	Username   string   `json:"username,omitempty"`
	CreatedBy  string   `json:"created_by"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  *string  `json:"expires_at"`
	LastUsedAt *string  `json:"last_used_at"`
	LastUsedIP string   `json:"last_used_ip,omitempty"`
	RevokedAt  *string  `json:"revoked_at"`
	Active     bool     `json:"active"`
}

func newTokenView(token *store.APIToken) tokenView {
	return tokenView{
		ID:         token.ID,
		Name:       token.Name,
		Prefix:     token.Prefix,
		Kind:       token.Kind,
		Scopes:     token.Scopes,
		Username:   token.Username,
		CreatedBy:  token.CreatedBy,
		CreatedAt:  token.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt:  formatTimePointer(token.ExpiresAt),
		LastUsedAt: formatTimePointer(token.LastUsedAt),
		LastUsedIP: token.LastUsedIP,
		RevokedAt:  formatTimePointer(token.RevokedAt),
		Active:     token.Active(time.Now()),
	}
}

// auditView is one audit event.
type auditView struct {
	ID         int    `json:"id"`
	Actor      string `json:"actor"`
	Action     string `json:"action"`
	TargetUser string `json:"target_user,omitempty"`
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
	IPAddress  string `json:"ip_address,omitempty"`
	Metadata   any    `json:"metadata,omitempty"`
	CreatedAt  string `json:"created_at"`
}

func newAuditView(event *store.AuditEvent) auditView {
	view := auditView{
		ID:         event.ID,
		Actor:      event.Actor,
		Action:     event.Action,
		TargetUser: event.TargetUser,
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		Reason:     event.Reason,
		IPAddress:  event.IPAddress,
		CreatedAt:  event.CreatedAt.UTC().Format(time.RFC3339),
	}
	if event.Metadata != "" {
		var decoded any
		if err := json.Unmarshal([]byte(event.Metadata), &decoded); err == nil {
			view.Metadata = decoded
		} else {
			view.Metadata = event.Metadata
		}
	}
	return view
}

// webhookView is a subscription. The signing secret is returned only when the
// subscription is created.
type webhookView struct {
	ID        int      `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Active    bool     `json:"active"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
}

func newWebhookView(webhook *store.Webhook) webhookView {
	return webhookView{
		ID:        webhook.ID,
		URL:       webhook.URL,
		Events:    webhook.Events,
		Active:    webhook.Active,
		CreatedBy: webhook.CreatedBy,
		CreatedAt: webhook.CreatedAt.UTC().Format(time.RFC3339),
	}
}

type deliveryView struct {
	ID          int    `json:"id"`
	WebhookID   int    `json:"webhook_id"`
	Event       string `json:"event"`
	StatusCode  int    `json:"status_code"`
	Error       string `json:"error,omitempty"`
	Attempts    int    `json:"attempts"`
	DeliveredAt string `json:"delivered_at"`
}

func newDeliveryView(delivery *store.WebhookDelivery) deliveryView {
	return deliveryView{
		ID:          delivery.ID,
		WebhookID:   delivery.WebhookID,
		Event:       delivery.Event,
		StatusCode:  delivery.StatusCode,
		Error:       delivery.Error,
		Attempts:    delivery.Attempts,
		DeliveredAt: delivery.DeliveredAt.UTC().Format(time.RFC3339),
	}
}
