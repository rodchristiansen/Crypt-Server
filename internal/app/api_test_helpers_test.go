package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

// newAPITestServer builds a server with the API mounted, backed by a real
// sqlite database so the filtered queries are exercised for real.
func newAPITestServer(t *testing.T) (*Server, store.Store) {
	t.Helper()
	codec := testCodec(t)
	dataStore := newTestSQLiteStore(t, codec)

	root := filepath.Join("..", "..")
	renderer := NewRenderer(
		filepath.Join(root, "web", "templates", "layouts", "base.html"),
		filepath.Join(root, "web", "templates", "pages"),
	)
	sessionManager, err := NewSessionManager([]byte("test-session-key-32-bytes-long!!"), "crypt_session", time.Hour)
	require.NoError(t, err)

	server := NewServer(
		dataStore,
		renderer,
		log.New(io.Discard, "", 0),
		sessionManager,
		NewCSRFManager("crypt_csrf", 32),
		nil,
		nil,
		Settings{
			ApproveOwn:             false,
			SessionTTL:             time.Hour,
			RequestCleanupInterval: 0,
			APIEnabled:             true,
			StaleAfter:             30 * 24 * time.Hour,
			RequestRetention:       7 * 24 * time.Hour,
		},
	)
	return server, dataStore
}

// mintTestToken creates a token of the given kind and scopes and returns the
// plaintext to present in tests.
func mintTestToken(t *testing.T, dataStore store.Store, kind string, scopes ...string) string {
	t.Helper()
	plaintext, _, err := MintToken(dataStore, "test-"+kind, kind, scopes, "", "test")
	require.NoError(t, err)
	return plaintext
}

// mintUserToken creates a personal access token acting as an existing user.
func mintUserToken(t *testing.T, dataStore store.Store, username string, scopes ...string) string {
	t.Helper()
	plaintext, _, err := MintToken(dataStore, "test-pat-"+username, store.TokenKindUser, scopes, username, "test")
	require.NoError(t, err)
	return plaintext
}

// apiRequest issues a request against the API with an optional bearer token
// and JSON body, and returns the recorded response.
func apiRequest(t *testing.T, server *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	}
	request := httptest.NewRequest(method, path, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

// decodeAPIBody unmarshals a recorded JSON response.
func decodeAPIBody(t *testing.T, recorder *httptest.ResponseRecorder, target any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), target))
}

// apiErrorCode reads the machine-readable code from an error response.
func apiErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body apiErrorBody
	decodeAPIBody(t, recorder, &body)
	return body.Error.Code
}

// seedComputerWithSecret creates a computer and escrows one secret for it.
func seedComputerWithSecret(t *testing.T, dataStore store.Store, serial, secretValue string) (*store.Computer, *store.Secret) {
	t.Helper()
	computer, err := dataStore.UpsertComputer(serial, "user", serial+"-name", time.Now())
	require.NoError(t, err)
	secret, _, err := dataStore.AddSecret(computer.ID, "recovery_key", secretValue, false)
	require.NoError(t, err)
	return computer, secret
}

// seedUser creates a user account for token and workflow tests.
func seedUser(t *testing.T, dataStore store.Store, username string, isStaff, canApprove bool) *store.User {
	t.Helper()
	user, err := dataStore.AddUser(username, "", isStaff, canApprove, false, false, "saml")
	require.NoError(t, err)
	return user
}

// requireStatus fails with the response body when the status is unexpected,
// which makes a failing API test readable without a second run.
func requireStatus(t *testing.T, recorder *httptest.ResponseRecorder, expected int) {
	t.Helper()
	require.Equal(t, expected, recorder.Code, "unexpected status; body: %s", recorder.Body.String())
}

var _ = http.MethodGet

// Test serials are deliberately synthetic so nothing in the public repository
// resembles a real machine identifier.
const (
	testSerialA = "TEST-SERIAL-AAA"
	testSerialB = "TEST-SERIAL-BBB"
	testSerialC = "TEST-SERIAL-CCC"
)
