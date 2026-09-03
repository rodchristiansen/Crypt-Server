package app

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"crypt-server/internal/store"
)

type webhookBody struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Active *bool    `json:"active"`
}

type createWebhookResponse struct {
	Webhook webhookView `json:"webhook"`
	// Secret signs deliveries. It is shown exactly once, here.
	Secret string `json:"secret"`
}

func (s *Server) resolveWebhook(w http.ResponseWriter, values pathValues) (*store.Webhook, bool) {
	id, err := strconv.Atoi(values["id"])
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "webhook_not_found", "No webhook with that id.", nil)
		return nil, false
	}
	webhook, err := s.store.GetWebhook(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "webhook_not_found", "No webhook with that id.", nil)
			return nil, false
		}
		s.logger.Printf("api: webhook lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return nil, false
	}
	return webhook, true
}

// validateWebhookBody checks the URL and event names.
func validateWebhookBody(body webhookBody) (string, []string, error) {
	target := strings.TrimSpace(body.URL)
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return "", nil, errInvalidWebhookURL
	}
	// Deliveries must be encrypted in transit. Plain http is allowed only to
	// loopback, where it never leaves the host, for local development.
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return "", nil, errInvalidWebhookURL
	}
	if len(body.Events) == 0 {
		return "", nil, errNoWebhookEvents
	}
	events := make([]string, 0, len(body.Events))
	for _, raw := range body.Events {
		event := strings.TrimSpace(raw)
		if event == "" {
			continue
		}
		if !IsKnownEvent(event) {
			return "", nil, errUnknownWebhookEvent
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		return "", nil, errNoWebhookEvents
	}
	return target, events, nil
}

// isLoopbackHost reports whether a hostname resolves to the local machine
// without leaving it.
func isLoopbackHost(hostname string) bool {
	switch hostname {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

var (
	errInvalidWebhookURL   = webhookValidationError("The URL must be an absolute https:// address (http is allowed only to loopback).")
	errNoWebhookEvents     = webhookValidationError("Subscribe to at least one event.")
	errUnknownWebhookEvent = webhookValidationError("One of the events is not one this server emits.")
)

type webhookValidationError string

func (e webhookValidationError) Error() string { return string(e) }

func (s *Server) handleAPIListWebhooks(w http.ResponseWriter, _ *http.Request, _ pathValues, _ *Principal) {
	webhooks, err := s.store.ListWebhooks()
	if err != nil {
		s.logger.Printf("api: list webhooks failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]webhookView, 0, len(webhooks))
	for _, webhook := range webhooks {
		results = append(results, newWebhookView(webhook))
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleAPICreateWebhook(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body webhookBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	target, events, err := validateWebhookBody(body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_webhook", err.Error(), nil)
		return
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		s.logger.Printf("api: webhook secret generation failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	active := true
	if body.Active != nil {
		active = *body.Active
	}

	created, err := s.store.AddWebhook(store.Webhook{
		URL:       target,
		Events:    events,
		Secret:    secret,
		Active:    active,
		CreatedBy: principal.Actor(),
		CreatedAt: time.Now(),
	})
	if err != nil {
		s.logger.Printf("api: create webhook failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventWebhookCreated,
		TargetType: "webhook",
		TargetID:   strconv.Itoa(created.ID),
		Metadata:   map[string]any{"url": created.URL, "events": created.Events},
	})
	writeAPIJSON(w, http.StatusCreated, createWebhookResponse{
		Webhook: newWebhookView(created),
		Secret:  secret,
	})
}

func (s *Server) handleAPIGetWebhook(w http.ResponseWriter, _ *http.Request, values pathValues, _ *Principal) {
	webhook, ok := s.resolveWebhook(w, values)
	if !ok {
		return
	}
	writeAPIJSON(w, http.StatusOK, newWebhookView(webhook))
}

func (s *Server) handleAPIPatchWebhook(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	webhook, ok := s.resolveWebhook(w, values)
	if !ok {
		return
	}
	var body webhookBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.URL) == "" {
		body.URL = webhook.URL
	}
	if len(body.Events) == 0 {
		body.Events = webhook.Events
	}
	target, events, err := validateWebhookBody(body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_webhook", err.Error(), nil)
		return
	}
	active := webhook.Active
	if body.Active != nil {
		active = *body.Active
	}
	updated, err := s.store.UpdateWebhook(webhook.ID, target, events, active)
	if err != nil {
		s.logger.Printf("api: update webhook failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventWebhookUpdated,
		TargetType: "webhook",
		TargetID:   strconv.Itoa(updated.ID),
		Metadata:   map[string]any{"url": updated.URL, "events": updated.Events, "active": updated.Active},
	})
	writeAPIJSON(w, http.StatusOK, newWebhookView(updated))
}

func (s *Server) handleAPIDeleteWebhook(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	webhook, ok := s.resolveWebhook(w, values)
	if !ok {
		return
	}
	if err := s.store.DeleteWebhook(webhook.ID); err != nil {
		s.logger.Printf("api: delete webhook failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventWebhookDeleted,
		TargetType: "webhook",
		TargetID:   strconv.Itoa(webhook.ID),
		Metadata:   map[string]any{"url": webhook.URL},
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}

// handleAPITestWebhook sends a synthetic event so an operator can confirm the
// endpoint and signature verification before relying on it.
func (s *Server) handleAPITestWebhook(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	webhook, ok := s.resolveWebhook(w, values)
	if !ok {
		return
	}
	event := store.AuditEvent{
		Actor:      principal.Actor(),
		Action:     "webhook.test",
		TargetType: "webhook",
		TargetID:   strconv.Itoa(webhook.ID),
		CreatedAt:  time.Now(),
		Metadata:   `{"test":true}`,
	}
	payload := webhookPayload{
		Event:      event.Action,
		OccurredAt: event.CreatedAt.UTC().Format(time.RFC3339),
		Actor:      event.Actor,
		TargetType: event.TargetType,
		TargetID:   event.TargetID,
		Metadata:   map[string]any{"test": true},
	}
	body, err := encodeJSON(payload)
	if err != nil {
		s.logger.Printf("api: encode test payload failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	go s.deliverWebhook(webhook, event.Action, body)
	writeAPIJSON(w, http.StatusAccepted, map[string]any{
		"status":     "queued",
		"webhook_id": webhook.ID,
	})
}

func (s *Server) handleAPIWebhookDeliveries(w http.ResponseWriter, r *http.Request, values pathValues, _ *Principal) {
	webhook, ok := s.resolveWebhook(w, values)
	if !ok {
		return
	}
	limit := queryInt(r, "limit", 50)
	if limit > maxPageSize {
		limit = maxPageSize
	}
	deliveries, err := s.store.ListWebhookDeliveries(webhook.ID, limit)
	if err != nil {
		s.logger.Printf("api: list deliveries failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]deliveryView, 0, len(deliveries))
	for _, delivery := range deliveries {
		results = append(results, newDeliveryView(delivery))
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"results": results})
}
