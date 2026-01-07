package app

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"crypt-server/internal/crypto"
	"crypt-server/internal/migrate"
	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*Server, store.Store, *SessionManager) {
	t.Helper()
	root := filepath.Join("..", "..")
	layout := filepath.Join(root, "web", "templates", "layouts", "base.html")
	pages := filepath.Join(root, "web", "templates", "pages")
	renderer := NewRenderer(layout, pages)
	codec := testCodec(t)
	dataStore := newTestSQLiteStore(t, codec)
	logger := log.New(io.Discard, "", 0)
	sessionManager, err := NewSessionManager([]byte("test-session-key-32-bytes-long!!"), "crypt_session", time.Hour)
	require.NoError(t, err)
	settings := Settings{
		ApproveOwn:             true,
		AllApprove:             false,
		SessionTTL:             time.Hour,
		CookieSecure:           false,
		RequestCleanupInterval: 0,
	}
	csrfManager := NewCSRFManager("crypt_csrf", 32)
	server := NewServer(dataStore, renderer, logger, sessionManager, csrfManager, nil, nil, settings)
	passwordHash := hashPasswordForTest(t, "password")
	_, err = dataStore.AddUser("admin", passwordHash, true, true, true, false, "local")
	require.NoError(t, err)
	return server, dataStore, sessionManager
}

func newTestSQLiteStore(t *testing.T, codec *crypto.AesGcmCodec) *store.SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crypt.db")
	sqliteStore, err := store.NewSQLiteStore(path, codec)
	require.NoError(t, err)
	migrationFS, err := migrate.SubMigrationsFS(migrate.EmbeddedFS, "sqlite")
	require.NoError(t, err)
	require.NoError(t, migrate.Apply(sqliteStore.DB(), "sqlite", migrationFS))
	return sqliteStore
}

func TestHandleIndex(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	_, err := memStore.AddComputer("SERIAL1", "user", "Mac")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/", nil, "admin")
	serveProtected(server, rec, req, server.handleIndex)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Serial Number")
}

func TestHandleTableAjax(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	_, err := memStore.AddComputer("SERIAL2", "user", "iMac")
	require.NoError(t, err)

	payload := map[string]any{"draw": 1}
	payloadBytes, _ := json.Marshal(payload)
	query := url.Values{}
	query.Set("args", string(payloadBytes))

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/ajax/?"+query.Encode(), nil, "admin")
	serveProtected(server, rec, req, server.handleTableAjax)

	require.Equal(t, http.StatusOK, rec.Code)

	var data map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &data))
	require.Equal(t, float64(1), data["recordsTotal"])
}

func TestHandleNewComputerFlow(t *testing.T) {
	server, _, sessionManager := newTestServer(t)
	form := url.Values{}
	form.Set("serial", "SERIAL3")
	form.Set("username", "user3")
	form.Set("computername", "MacBook Air")

	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/new/computer/", form, "admin")
	serveProtected(server, rec, req, server.handleNewComputer)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/info/")
}

func TestRequestApproveRetrieveFlow(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	computer, err := memStore.AddComputer("SERIAL4", "user4", "MacBook Pro")
	require.NoError(t, err)
	secret, err := memStore.AddSecret(computer.ID, "recovery_key", "secret-value", false)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("reason_for_request", "Need access")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/request/"+intToString(secret.ID)+"/", form, "admin")
	serveProtected(server, rec, req, server.handleRequest)

	require.Equal(t, http.StatusSeeOther, rec.Code)

	requests, err := memStore.ListRequestsBySecret(secret.ID)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	infoRec := httptest.NewRecorder()
	infoReq := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/info/secret/"+intToString(secret.ID)+"/", nil, "admin")
	serveProtected(server, infoRec, infoReq, server.handleSecretInfo)
	require.Contains(t, infoRec.Body.String(), "Retrieve Key")

	retrieveRec := httptest.NewRecorder()
	retrieveReq := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/retrieve/"+intToString(requests[0].ID)+"/", nil, "admin")
	serveProtected(server, retrieveRec, retrieveReq, server.handleRetrieve)
	require.Equal(t, http.StatusOK, retrieveRec.Code)
	require.Contains(t, retrieveRec.Body.String(), "class=\"letter\">s")
}

func TestHandleManageRequests(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	computer, err := memStore.AddComputer("SERIAL5", "user5", "Mac Mini")
	require.NoError(t, err)
	secret, err := memStore.AddSecret(computer.ID, "password", "secret", false)
	require.NoError(t, err)
	_, err = memStore.AddRequest(secret.ID, "user5", "Need access", "", nil)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/manage-requests/", nil, "admin")
	serveProtected(server, rec, req, server.handleManageRequests)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "SERIAL5")
}

func TestIDFromPath(t *testing.T) {
	id, err := idFromPath("/info/", "/info/123/")
	require.NoError(t, err)
	require.Equal(t, 123, id)

	_, err = idFromPath("/info/", "/other/123/")
	require.Error(t, err)
}

func TestLookupComputer(t *testing.T) {
	server, memStore, _ := newTestServer(t)
	computer, err := memStore.AddComputer("SERIAL6", "user", "Mac Studio")
	require.NoError(t, err)

	byID, err := server.lookupComputer(intToString(computer.ID))
	require.NoError(t, err)
	require.Equal(t, "SERIAL6", byID.Serial)

	bySerial, err := server.lookupComputer("serial6")
	require.NoError(t, err)
	require.Equal(t, computer.ID, bySerial.ID)
}

func TestCheckinCreatesSecret(t *testing.T) {
	server, memStore, _ := newTestServer(t)

	form := url.Values{}
	form.Set("serial", "SERIALCHECKIN")
	form.Set("recovery_password", "secret-value")
	form.Set("username", "user1")
	form.Set("macname", "MacBook")
	form.Set("secret_type", "recovery_key")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/checkin/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleCheckin(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "\"serial\":\"SERIALCHECKIN\"")
	require.Contains(t, rec.Body.String(), "\"rotation_required\":false")

	computer, err := memStore.GetComputerBySerial("SERIALCHECKIN")
	require.NoError(t, err)
	require.Equal(t, "user1", computer.Username)
}

func TestVerifyEscrowed(t *testing.T) {
	server, memStore, _ := newTestServer(t)
	computer, err := memStore.AddComputer("SERIALVERIFY", "user", "Mac")
	require.NoError(t, err)
	_, err = memStore.AddSecret(computer.ID, "recovery_key", "secret", false)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify/SERIALVERIFY/recovery_key/", nil)
	server.handleVerify(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "\"escrowed\":true")
	require.Contains(t, rec.Body.String(), "\"date_escrowed\"")
}

func TestVerifyNotEscrowed(t *testing.T) {
	server, memStore, _ := newTestServer(t)
	_, err := memStore.AddComputer("SERIALVERIFY2", "user", "Mac")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify/SERIALVERIFY2/recovery_key/", nil)
	server.handleVerify(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "\"escrowed\":false")
}

func TestVerifyMissingComputer(t *testing.T) {
	server, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/verify/UNKNOWN/recovery_key/", nil)
	server.handleVerify(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleLoginSuccess(t *testing.T) {
	server, _, _ := newTestServer(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "password")
	form.Set("next", "/")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleLogin(rec, req)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.NotEmpty(t, rec.Header().Get("Set-Cookie"))
}

func TestHandleLoginFailure(t *testing.T) {
	server, _, _ := newTestServer(t)

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "wrong")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleLogin(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Invalid username or password.")
}

func TestHandleLoginRequiresLocalLogin(t *testing.T) {
	server, memStore, _ := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := memStore.AddUser("samluser", passwordHash, false, false, false, false, "saml")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("username", "samluser")
	form.Set("password", "password")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleLogin(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Invalid username or password.")
}

func TestHandleLoginRedirectsToReset(t *testing.T) {
	server, memStore, _ := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := memStore.AddUser("resetme", passwordHash, false, false, true, true, "local")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("username", "resetme")
	form.Set("password", "password")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleLogin(rec, req)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/password/reset/", rec.Header().Get("Location"))
}

func TestHandlePasswordChange(t *testing.T) {
	server, _, sessionManager := newTestServer(t)

	form := url.Values{}
	form.Set("current_password", "password")
	form.Set("new_password", "Str0ng!Passw0rd")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/password/change/", form, "admin")
	serveProtected(server, rec, req, server.handlePasswordChange)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/", rec.Header().Get("Location"))
}

func TestHandlePasswordResetClearsFlag(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	resetUser, err := memStore.AddUser("resetuser", passwordHash, false, false, true, true, "local")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("new_password", "Str0ng!Passw0rd")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/password/reset/", form, "resetuser")
	serveProtected(server, rec, req, server.handlePasswordReset)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	updated, err := memStore.GetUserByID(resetUser.ID)
	require.NoError(t, err)
	require.False(t, updated.MustResetPassword)
	require.True(t, verifyPassword("Str0ng!Passw0rd", updated.PasswordHash))
}

func TestHandleSAMLLoginStub(t *testing.T) {
	server, _, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/saml/login/", nil)
	server.handleSAMLLogin(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestHandleUserListRequiresStaff(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := memStore.AddUser("viewer", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/admin/users/", nil, "viewer")
	serveProtected(server, rec, req, server.handleUserList)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleUserList(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := memStore.AddUser("second", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/admin/users/", nil, "admin")
	serveProtected(server, rec, req, server.handleUserList)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "admin")
	require.Contains(t, rec.Body.String(), "second")
}

func TestHandleNewUser(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)

	form := url.Values{}
	form.Set("username", "newuser")
	form.Set("password", "Str0ng!Passw0rd")
	form.Set("local_login_enabled", "on")
	form.Set("auth_source", "local")
	form.Set("is_staff", "on")
	form.Set("can_approve", "on")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/new/", form, "admin")
	serveProtected(server, rec, req, server.handleNewUser)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	user, err := memStore.GetUserByUsername("newuser")
	require.NoError(t, err)
	require.True(t, user.IsStaff)
	require.True(t, user.CanApprove)
	require.True(t, user.LocalLoginEnabled)
	require.Equal(t, "local", user.AuthSource)
	require.True(t, verifyPassword("Str0ng!Passw0rd", user.PasswordHash))
}

func TestHandleUserEdit(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	target, err := memStore.AddUser("editor", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("username", "updated")
	form.Set("is_staff", "on")
	form.Set("can_approve", "on")
	form.Set("local_login_enabled", "on")
	form.Set("must_reset_password", "on")
	form.Set("auth_source", "saml")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/edit/", form, "admin")
	serveProtected(server, rec, req, server.handleUserEdit)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	updated, err := memStore.GetUserByID(target.ID)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Username)
	require.True(t, updated.IsStaff)
	require.True(t, updated.CanApprove)
	require.True(t, updated.MustResetPassword)
	require.Equal(t, "saml", updated.AuthSource)
}

func TestHandleUserPassword(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	target, err := memStore.AddUser("reset", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("password", "Str0ng!Passw0rd")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/password/", form, "admin")
	serveProtected(server, rec, req, server.handleUserPassword)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	updated, err := memStore.GetUserByID(target.ID)
	require.NoError(t, err)
	require.True(t, verifyPassword("Str0ng!Passw0rd", updated.PasswordHash))
	require.False(t, updated.MustResetPassword)
}

func TestHandleUserDelete(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	target, err := memStore.AddUser("remove", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/delete/", url.Values{}, "admin")
	serveProtected(server, rec, req, server.handleUserDelete)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	_, err = memStore.GetUserByID(target.ID)
	require.Error(t, err)
}

func TestHandleUserDeleteSelf(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	admin, err := memStore.GetUserByUsername("admin")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/"+intToString(admin.ID)+"/delete/", url.Values{}, "admin")
	serveProtected(server, rec, req, server.handleUserDelete)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "You cannot delete your own account.")
}

func intToString(value int) string {
	return strconv.Itoa(value)
}

func newAuthenticatedRequest(t *testing.T, sessionManager *SessionManager, method, target string, body io.Reader, username string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	token, err := sessionManager.Create(username)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: sessionManager.CookieName(), Value: token})
	return req
}

func newAuthenticatedFormRequest(t *testing.T, server *Server, sessionManager *SessionManager, method, target string, form url.Values, username string) *http.Request {
	t.Helper()
	csrfToken, err := server.csrfManager.GenerateToken()
	require.NoError(t, err)
	form.Set("csrf_token", csrfToken)
	req := newAuthenticatedRequest(t, sessionManager, method, target, strings.NewReader(form.Encode()), username)
	req.AddCookie(&http.Cookie{Name: server.csrfManager.cookieName, Value: csrfToken})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func serveProtected(server *Server, rec *httptest.ResponseRecorder, req *http.Request, handler http.HandlerFunc) {
	server.withCSRF(server.withUser(http.HandlerFunc(server.requireAuth(handler)))).ServeHTTP(rec, req)
}

func hashPasswordForTest(t *testing.T, password string) string {
	t.Helper()
	hash, err := hashPassword(password)
	require.NoError(t, err)
	return hash
}

func testCodec(t *testing.T) *crypto.AesGcmCodec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	codec, err := crypto.NewAesGcmCodecFromBase64Key(encoded)
	require.NoError(t, err)
	return codec
}
