package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

// capturedDelivery is one webhook POST observed by the test receiver.
type capturedDelivery struct {
	body      []byte
	signature string
	timestamp string
	event     string
}

// newWebhookReceiver starts a server that records the deliveries it receives.
func newWebhookReceiver(t *testing.T) (*httptest.Server, func() []capturedDelivery) {
	t.Helper()
	var mutex sync.Mutex
	captured := make([]capturedDelivery, 0)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mutex.Lock()
		captured = append(captured, capturedDelivery{
			body:      body,
			signature: r.Header.Get("X-Crypt-Signature"),
			timestamp: r.Header.Get("X-Crypt-Timestamp"),
			event:     r.Header.Get("X-Crypt-Event"),
		})
		mutex.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)
	return receiver, func() []capturedDelivery {
		mutex.Lock()
		defer mutex.Unlock()
		snapshot := make([]capturedDelivery, len(captured))
		copy(snapshot, captured)
		return snapshot
	}
}

// waitForDeliveries polls until the expected number of deliveries arrive.
func waitForDeliveries(t *testing.T, read func() []capturedDelivery, want int) []capturedDelivery {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := read(); len(got) >= want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.FailNowf(t, "webhook deliveries did not arrive", "wanted %d, got %d", want, len(read()))
	return nil
}

func TestWebhookRejectsNonHTTPSURL(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL:    "http://example.invalid/hook",
		Events: []string{EventSecretEscrowed},
	})

	requireStatus(t, recorder, http.StatusBadRequest)
	require.Equal(t, "invalid_webhook", apiErrorCode(t, recorder))
}

func TestWebhookRejectsUnknownEvent(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL:    "https://example.invalid/hook",
		Events: []string{"secret.exfiltrated"},
	})

	requireStatus(t, recorder, http.StatusBadRequest)
}

func TestWebhookCreateReturnsSecretOnce(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL:    "https://example.invalid/hook",
		Events: []string{EventSecretEscrowed},
	})
	requireStatus(t, created, http.StatusCreated)
	var body createWebhookResponse
	decodeAPIBody(t, created, &body)
	require.NotEmpty(t, body.Secret)

	fetched := apiRequest(t, server, http.MethodGet, "/api/v1/webhooks/"+strconv.Itoa(body.Webhook.ID), admin, nil)
	require.NotContains(t, fetched.Body.String(), body.Secret)
}

func TestWebhookDeliversSignedEscrowEventWithoutTheSecret(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.settings.WebhooksEnabled = true
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)
	device := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	receiver, read := newWebhookReceiver(t)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL:    receiver.URL,
		Events: []string{EventSecretEscrowed},
	})
	requireStatus(t, created, http.StatusCreated)
	var webhook createWebhookResponse
	decodeAPIBody(t, created, &webhook)

	escrow := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", device, escrowRequest{
		Serial:   testSerialA,
		Username: "someone",
		Secret:   "SENSITIVE-VALUE",
	})
	requireStatus(t, escrow, http.StatusCreated)

	deliveries := waitForDeliveries(t, read, 1)
	delivery := deliveries[0]
	require.Equal(t, EventSecretEscrowed, delivery.event)
	require.NotContains(t, string(delivery.body), "SENSITIVE-VALUE")

	// The signature covers the timestamp and the body.
	mac := hmac.New(sha256.New, []byte(webhook.Secret))
	mac.Write([]byte(delivery.timestamp + "."))
	mac.Write(delivery.body)
	require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), delivery.signature)

	var payload webhookPayload
	require.NoError(t, json.Unmarshal(delivery.body, &payload))
	require.Equal(t, "secret", payload.TargetType)
}

func TestWebhookOnlyDeliversSubscribedEvents(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.settings.WebhooksEnabled = true
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)
	device := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	receiver, read := newWebhookReceiver(t)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL:    receiver.URL,
		Events: []string{EventComputerDeleted},
	})
	requireStatus(t, created, http.StatusCreated)

	escrow := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", device, escrowRequest{
		Serial: testSerialA, Username: "someone", Secret: "AAAA",
	})
	requireStatus(t, escrow, http.StatusCreated)

	time.Sleep(150 * time.Millisecond)
	require.Empty(t, read())
}

func TestWebhookDeliveriesAreRecorded(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.settings.WebhooksEnabled = true
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)
	device := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	receiver, read := newWebhookReceiver(t)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL:    receiver.URL,
		Events: []string{"*"},
	})
	var webhook createWebhookResponse
	decodeAPIBody(t, created, &webhook)

	escrow := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", device, escrowRequest{
		Serial: testSerialA, Username: "someone", Secret: "AAAA",
	})
	requireStatus(t, escrow, http.StatusCreated)
	waitForDeliveries(t, read, 1)

	// The delivery row is written after the receiver replies, so poll for it.
	var body struct {
		Results []deliveryView `json:"results"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		listing := apiRequest(t, server, http.MethodGet,
			"/api/v1/webhooks/"+strconv.Itoa(webhook.Webhook.ID)+"/deliveries", admin, nil)
		requireStatus(t, listing, http.StatusOK)
		decodeAPIBody(t, listing, &body)
		if len(body.Results) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	require.NotEmpty(t, body.Results)
	require.Equal(t, http.StatusOK, body.Results[0].StatusCode)
}

func TestWebhooksStayQuietWhenDisabled(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)
	device := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	receiver, read := newWebhookReceiver(t)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/webhooks", admin, webhookBody{
		URL: receiver.URL, Events: []string{"*"},
	})
	requireStatus(t, created, http.StatusCreated)

	escrow := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", device, escrowRequest{
		Serial: testSerialA, Username: "someone", Secret: "AAAA",
	})
	requireStatus(t, escrow, http.StatusCreated)

	time.Sleep(150 * time.Millisecond)
	require.Empty(t, read())
}
