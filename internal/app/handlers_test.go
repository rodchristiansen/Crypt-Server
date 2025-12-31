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
	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*Server, *store.MemoryStore, *SessionManager) {
	t.Helper()
	root := filepath.Join("..", "..")
	layout := filepath.Join(root, "web", "templates", "layouts", "base.html")
	pages := filepath.Join(root, "web", "templates", "pages")
	renderer := NewRenderer(layout, pages)
	codec := testCodec(t)
	memStore := store.NewMemoryStore(codec)
	logger := log.New(io.Discard, "", 0)
	sessionManager, err := NewSessionManager([]byte("test-session-key-32-bytes-long!!"), "crypt_session", time.Hour)
	require.NoError(t, err)
	settings := Settings{
		ApproveOwn:   true,
		AllApprove:   false,
		SessionTTL:   time.Hour,
		CookieSecure: false,
	}
	server := NewServer(memStore, renderer, logger, sessionManager, settings)
	passwordHash := hashPasswordForTest(t, "password")
	_, err = memStore.AddUser("admin", passwordHash, true, true, true)
	require.NoError(t, err)
	return server, memStore, sessionManager
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
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/new/computer/", strings.NewReader(form.Encode()), "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/request/"+intToString(secret.ID)+"/", strings.NewReader(form.Encode()), "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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

func TestCheckinVerifyStubs(t *testing.T) {
	server, _, _ := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/checkin/", nil)
	server.handleCheckin(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/verify/serial/type/", nil)
	server.handleVerify(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)
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

func TestHandleUserListRequiresStaff(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := memStore.AddUser("viewer", passwordHash, false, false, true)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/admin/users/", nil, "viewer")
	serveProtected(server, rec, req, server.handleUserList)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleUserList(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := memStore.AddUser("second", passwordHash, false, false, true)
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
	form.Set("password", "newpass")
	form.Set("has_usable_password", "on")
	form.Set("is_staff", "on")
	form.Set("can_approve", "on")
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/admin/users/new/", strings.NewReader(form.Encode()), "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	serveProtected(server, rec, req, server.handleNewUser)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	user, err := memStore.GetUserByUsername("newuser")
	require.NoError(t, err)
	require.True(t, user.IsStaff)
	require.True(t, user.CanApprove)
	require.True(t, verifyPassword("newpass", user.PasswordHash))
}

func TestHandleUserEdit(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	target, err := memStore.AddUser("editor", passwordHash, false, false, true)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("username", "updated")
	form.Set("is_staff", "on")
	form.Set("can_approve", "on")
	form.Set("has_usable_password", "on")
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/edit/", strings.NewReader(form.Encode()), "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	serveProtected(server, rec, req, server.handleUserEdit)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	updated, err := memStore.GetUserByID(target.ID)
	require.NoError(t, err)
	require.Equal(t, "updated", updated.Username)
	require.True(t, updated.IsStaff)
	require.True(t, updated.CanApprove)
}

func TestHandleUserPassword(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	target, err := memStore.AddUser("reset", passwordHash, false, false, true)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("password", "newpass")
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/password/", strings.NewReader(form.Encode()), "admin")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	serveProtected(server, rec, req, server.handleUserPassword)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	updated, err := memStore.GetUserByID(target.ID)
	require.NoError(t, err)
	require.True(t, verifyPassword("newpass", updated.PasswordHash))
}

func TestHandleUserDelete(t *testing.T) {
	server, memStore, sessionManager := newTestServer(t)
	passwordHash := hashPasswordForTest(t, "password")
	target, err := memStore.AddUser("remove", passwordHash, false, false, true)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/delete/", nil, "admin")
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
	req := newAuthenticatedRequest(t, sessionManager, http.MethodPost, "/admin/users/"+intToString(admin.ID)+"/delete/", nil, "admin")
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

func serveProtected(server *Server, rec *httptest.ResponseRecorder, req *http.Request, handler http.HandlerFunc) {
	server.withUser(http.HandlerFunc(server.requireAuth(handler))).ServeHTTP(rec, req)
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
