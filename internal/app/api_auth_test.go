package app

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

func TestAPIHealthNeedsNoCredential(t *testing.T) {
	server, _ := newAPITestServer(t)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/health", "", nil)

	requireStatus(t, recorder, http.StatusOK)
	var body map[string]any
	decodeAPIBody(t, recorder, &body)
	require.Equal(t, "ok", body["status"])
}

func TestAPIRejectsMissingCredential(t *testing.T) {
	server, _ := newAPITestServer(t)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/computers", "", nil)

	requireStatus(t, recorder, http.StatusUnauthorized)
	require.Equal(t, "unauthenticated", apiErrorCode(t, recorder))
	require.NotEmpty(t, recorder.Header().Get("WWW-Authenticate"))
}

func TestAPIRejectsForgedToken(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	valid := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)

	// Same prefix, wrong secret.
	prefix, _, err := splitToken(valid)
	require.NoError(t, err)
	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/computers", prefix+".not-the-secret", nil)

	requireStatus(t, recorder, http.StatusUnauthorized)
}

func TestAPIRejectsInsufficientScope(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/audit", token, nil)

	requireStatus(t, recorder, http.StatusForbidden)
	require.Equal(t, "insufficient_scope", apiErrorCode(t, recorder))
}

func TestAPIAdminScopeImpliesEveryScope(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/audit", token, nil)

	requireStatus(t, recorder, http.StatusOK)
}

func TestAPIRejectsRevokedToken(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	plaintext, token, err := MintToken(dataStore, "revoked", store.TokenKindService, []string{store.ScopeComputersRead}, "", "test")
	require.NoError(t, err)
	require.NoError(t, dataStore.RevokeAPIToken(token.ID, time.Now()))

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/computers", plaintext, nil)

	requireStatus(t, recorder, http.StatusUnauthorized)
}

func TestAPIRejectsExpiredToken(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	expired := time.Now().Add(-time.Hour)
	plaintext, prefix, hash, err := generateToken(store.TokenKindService)
	require.NoError(t, err)
	_, err = dataStore.AddAPIToken(store.APIToken{
		Name:      "already-expired",
		Prefix:    prefix,
		TokenHash: hash,
		Kind:      store.TokenKindService,
		Scopes:    []string{store.ScopeComputersRead},
		CreatedBy: "test",
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: &expired,
	})
	require.NoError(t, err)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/computers", plaintext, nil)

	requireStatus(t, recorder, http.StatusUnauthorized)
}

func TestAPIAcceptsLegacySharedKeyForEscrowOnly(t *testing.T) {
	server, _ := newAPITestServer(t)
	server.settings.LegacyAPIKey = "legacy-shared-key"

	escrow := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", "legacy-shared-key", escrowRequest{
		Serial:   testSerialA,
		Username: "user",
		Secret:   "ABCD-1234",
	})
	requireStatus(t, escrow, http.StatusCreated)

	computers := apiRequest(t, server, http.MethodGet, "/api/v1/computers", "legacy-shared-key", nil)
	requireStatus(t, computers, http.StatusForbidden)
}

func TestAPIAcceptsXAPIKeyHeader(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/computers", nil)
	request.Header.Set("X-API-Key", token)
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)

	requireStatus(t, recorder, http.StatusOK)
}

func TestMintTokenRejectsRevealScopeOnDeviceToken(t *testing.T) {
	_, dataStore := newAPITestServer(t)

	_, _, err := MintToken(dataStore, "device", store.TokenKindDevice,
		[]string{store.ScopeEscrowWrite, store.ScopeSecretsReveal}, "", "test")

	require.Error(t, err)
	require.Contains(t, err.Error(), store.ScopeSecretsReveal)
}

func TestMintTokenRejectsUnknownScope(t *testing.T) {
	_, dataStore := newAPITestServer(t)

	_, _, err := MintToken(dataStore, "bad", store.TokenKindService, []string{"secrets:everything"}, "", "test")

	require.Error(t, err)
}

func TestTokenSecretIsNotStored(t *testing.T) {
	_, dataStore := newAPITestServer(t)

	plaintext, created, err := MintToken(dataStore, "hashing", store.TokenKindService, []string{store.ScopeComputersRead}, "", "test")
	require.NoError(t, err)

	_, secret, err := splitToken(plaintext)
	require.NoError(t, err)
	require.NotContains(t, created.TokenHash, secret)
	require.Equal(t, hashToken(secret), created.TokenHash)
}

func TestUserTokenCannotExceedItsOwner(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "reader", false, false)
	// The token asks for user administration; its owner is not staff.
	token := mintUserToken(t, dataStore, "reader", store.ScopeUsersWrite, store.ScopeComputersRead)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/users", token, nil)
	requireStatus(t, recorder, http.StatusForbidden)

	allowed := apiRequest(t, server, http.MethodGet, "/api/v1/computers", token, nil)
	requireStatus(t, allowed, http.StatusOK)
}

func TestAPIMeDescribesThePrincipal(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "approver", false, true)
	token := mintUserToken(t, dataStore, "approver", store.ScopeRequestsApprove, store.ScopeRequestsRead)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/users/me", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	var body meResponse
	decodeAPIBody(t, recorder, &body)
	require.Equal(t, "approver", body.Username)
	require.True(t, body.CanApprove)
	require.False(t, body.ViaSession)
	require.Contains(t, body.Scopes, store.ScopeRequestsApprove)
}

func TestAPIUnknownPathIs404AndWrongMethodIs405(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	missing := apiRequest(t, server, http.MethodGet, "/api/v1/nope", token, nil)
	requireStatus(t, missing, http.StatusNotFound)

	wrongMethod := apiRequest(t, server, http.MethodPut, "/api/v1/computers", token, nil)
	requireStatus(t, wrongMethod, http.StatusMethodNotAllowed)
}

func TestAPISessionWriteRequiresCSRFHeader(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "staffer", true, true)
	sessionToken, err := server.sessionManager.Create("staffer")
	require.NoError(t, err)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/computers", nil)
	request.AddCookie(&http.Cookie{Name: "crypt_session", Value: sessionToken})
	request.AddCookie(&http.Cookie{Name: "crypt_csrf", Value: "csrf-value"})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)

	requireStatus(t, recorder, http.StatusForbidden)
	require.Equal(t, "csrf_token_invalid", apiErrorCode(t, recorder))
}
