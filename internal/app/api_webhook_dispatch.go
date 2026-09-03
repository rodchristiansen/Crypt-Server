package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"crypt-server/internal/store"
)

const (
	webhookTimeout     = 10 * time.Second
	webhookMaxAttempts = 3
	webhookRetryDelay  = 2 * time.Second
)

// webhookPayload is the body delivered to a subscriber. It carries
// identifiers only: a secret is never sent to a webhook.
type webhookPayload struct {
	Event      string `json:"event"`
	OccurredAt string `json:"occurred_at"`
	Actor      string `json:"actor"`
	TargetType string `json:"target_type,omitempty"`
	TargetID   string `json:"target_id,omitempty"`
	TargetUser string `json:"target_user,omitempty"`
	Metadata   any    `json:"metadata,omitempty"`
}

// signPayload computes the signature sent in X-Crypt-Signature. The timestamp
// is signed alongside the body so a captured delivery cannot be replayed.
func signPayload(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// dispatchWebhooks delivers an event to every active subscriber. Delivery runs
// in the background so a slow subscriber never delays an API response.
func (s *Server) dispatchWebhooks(event store.AuditEvent) {
	if !s.settings.WebhooksEnabled {
		return
	}
	webhooks, err := s.store.ListWebhooks()
	if err != nil {
		s.logger.Printf("api: list webhooks failed: %v", err)
		return
	}
	subscribers := make([]*store.Webhook, 0, len(webhooks))
	for _, webhook := range webhooks {
		if webhook.Subscribed(event.Action) {
			subscribers = append(subscribers, webhook)
		}
	}
	if len(subscribers) == 0 {
		return
	}

	payload := webhookPayload{
		Event:      event.Action,
		OccurredAt: event.CreatedAt.UTC().Format(time.RFC3339),
		Actor:      event.Actor,
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		TargetUser: event.TargetUser,
	}
	if event.Metadata != "" {
		var decoded any
		if err := json.Unmarshal([]byte(event.Metadata), &decoded); err == nil {
			payload.Metadata = decoded
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Printf("api: encode webhook payload failed: %v", err)
		return
	}

	for _, webhook := range subscribers {
		go s.deliverWebhook(webhook, event.Action, body)
	}
}

// deliverWebhook posts one payload, retrying a small number of times, and
// records the outcome.
func (s *Server) deliverWebhook(webhook *store.Webhook, event string, body []byte) {
	client := s.webhookClient
	if client == nil {
		client = &http.Client{Timeout: webhookTimeout}
	}

	var lastStatus int
	var lastError string
	attempts := 0
	for attempts < webhookMaxAttempts {
		attempts++
		timestamp := time.Now().Unix()
		request, err := http.NewRequest(http.MethodPost, webhook.URL, bytes.NewReader(body))
		if err != nil {
			lastError = err.Error()
			break
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "crypt-server/"+Version)
		request.Header.Set("X-Crypt-Event", event)
		request.Header.Set("X-Crypt-Timestamp", strconv.FormatInt(timestamp, 10))
		request.Header.Set("X-Crypt-Signature", signPayload(webhook.Secret, timestamp, body))

		response, err := client.Do(request)
		if err != nil {
			lastError = err.Error()
		} else {
			lastStatus = response.StatusCode
			response.Body.Close()
			lastError = ""
			if lastStatus >= 200 && lastStatus < 300 {
				break
			}
			lastError = "unexpected status " + strconv.Itoa(lastStatus)
		}
		if attempts < webhookMaxAttempts {
			time.Sleep(webhookRetryDelay)
		}
	}

	delivery := store.WebhookDelivery{
		WebhookID:   webhook.ID,
		Event:       event,
		Payload:     string(body),
		StatusCode:  lastStatus,
		Error:       lastError,
		Attempts:    attempts,
		DeliveredAt: time.Now(),
	}
	if _, err := s.store.AddWebhookDelivery(delivery); err != nil {
		s.logger.Printf("api: record webhook delivery failed: %v", err)
	}
	if lastError != "" {
		s.logger.Printf("api: webhook %d delivery failed after %d attempts: %s", webhook.ID, attempts, lastError)
	}
}
