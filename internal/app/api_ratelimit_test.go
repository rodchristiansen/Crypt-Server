package app

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

func TestRateLimiterAllowsUpToTheLimitThenRefuses(t *testing.T) {
	limiter := newRateLimiter(2, time.Minute)

	for i := 0; i < 2; i++ {
		allowed, _ := limiter.allow("caller")
		require.True(t, allowed, "attempt %d should be allowed", i+1)
	}

	allowed, retryAfter := limiter.allow("caller")
	require.False(t, allowed)
	require.Positive(t, retryAfter)
}

func TestRateLimiterIsPerCaller(t *testing.T) {
	limiter := newRateLimiter(1, time.Minute)

	first, _ := limiter.allow("one")
	second, _ := limiter.allow("two")
	third, _ := limiter.allow("one")

	require.True(t, first)
	require.True(t, second)
	require.False(t, third)
}

func TestRateLimiterWindowExpires(t *testing.T) {
	limiter := newRateLimiter(1, time.Minute)
	now := time.Now()
	limiter.now = func() time.Time { return now }

	allowed, _ := limiter.allow("caller")
	require.True(t, allowed)
	blocked, _ := limiter.allow("caller")
	require.False(t, blocked)

	now = now.Add(time.Minute + time.Second)
	afterWindow, _ := limiter.allow("caller")
	require.True(t, afterWindow)
}

func TestRateLimiterDisabledAtZero(t *testing.T) {
	limiter := newRateLimiter(0, time.Minute)

	for i := 0; i < 100; i++ {
		allowed, _ := limiter.allow("caller")
		require.True(t, allowed)
	}
}

func TestAPIRevealIsRateLimited(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.revealLimiter = newRateLimiter(2, time.Minute)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeSecretsReveal)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")
	path := "/api/v1/secrets/" + strconv.Itoa(secret.ID) + "/value"

	requireStatus(t, apiRequest(t, server, http.MethodGet, path, token, nil), http.StatusOK)
	requireStatus(t, apiRequest(t, server, http.MethodGet, path, token, nil), http.StatusOK)

	limited := apiRequest(t, server, http.MethodGet, path, token, nil)
	requireStatus(t, limited, http.StatusTooManyRequests)
	require.Equal(t, "rate_limited", apiErrorCode(t, limited))
	require.NotEmpty(t, limited.Header().Get("Retry-After"))
	require.NotContains(t, limited.Body.String(), "SENSITIVE-VALUE")
}

func TestAPIRateLimitDoesNotAffectMetadataReads(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.revealLimiter = newRateLimiter(1, time.Minute)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeSecretsReveal, store.ScopeSecretsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	requireStatus(t, apiRequest(t, server, http.MethodGet,
		"/api/v1/secrets/"+strconv.Itoa(secret.ID)+"/value", token, nil), http.StatusOK)

	for i := 0; i < 5; i++ {
		requireStatus(t, apiRequest(t, server, http.MethodGet,
			"/api/v1/secrets/"+strconv.Itoa(secret.ID), token, nil), http.StatusOK)
	}
}

func TestAPIRetrieveIsRateLimited(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.settings.ApproveOwn = true
	server.revealLimiter = newRateLimiter(1, time.Minute)
	seedUser(t, dataStore, "approver", false, true)
	token := mintUserToken(t, dataStore, "approver", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", token,
		createRequestBody{SecretID: secret.ID, Reason: "need it"})
	requireStatus(t, created, http.StatusCreated)
	var request requestView
	decodeAPIBody(t, created, &request)
	path := "/api/v1/requests/" + strconv.Itoa(request.ID) + "/retrieve"

	requireStatus(t, apiRequest(t, server, http.MethodPost, path, token, nil), http.StatusOK)
	requireStatus(t, apiRequest(t, server, http.MethodPost, path, token, nil), http.StatusTooManyRequests)
}
