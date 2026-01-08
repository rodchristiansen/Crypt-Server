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
	codec := testCodec(t)
	dataStore := newTestSQLiteStore(t, codec)
	server, sessionManager := newTestServerWithStore(t, dataStore)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := dataStore.AddUser("admin", passwordHash, true, true, true, false, "local")
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

func newTestServerWithStore(t *testing.T, dataStore store.Store) (*Server, *SessionManager) {
	t.Helper()
	root := filepath.Join("..", "..")
	layout := filepath.Join(root, "web", "templates", "layouts", "base.html")
	pages := filepath.Join(root, "web", "templates", "pages")
	renderer := NewRenderer(layout, pages)
	logger := log.New(io.Discard, "", 0)
	sessionManager, err := NewSessionManager([]byte("test-session-key-32-bytes-long!!"), "crypt_session", time.Hour)
	require.NoError(t, err)
	settings := Settings{
		ApproveOwn:             true,
		AllApprove:             false,
		SessionTTL:             time.Hour,
		CookieSecure:           false,
		RequestCleanupInterval: 0,
		RotateViewedSecrets:    false,
	}
	csrfManager := NewCSRFManager("crypt_csrf", 32)
	server := NewServer(dataStore, renderer, logger, sessionManager, csrfManager, nil, nil, settings)
	return server, sessionManager
}

type rotationTrackingStore struct {
	*store.SQLiteStore
	called bool
}

func (s *rotationTrackingStore) SetSecretRotationRequired(secretID int, rotationRequired bool) (*store.Secret, error) {
	s.called = true
	return s.SQLiteStore.SetSecretRotationRequired(secretID, rotationRequired)
}

type auditPaginationStore struct {
	lastLimit  int
	lastOffset int
}

func (s *auditPaginationStore) ListAuditEventsPaged(limit, offset int) ([]*store.AuditEvent, error) {
	s.lastLimit = limit
	s.lastOffset = offset
	return []*store.AuditEvent{}, nil
}

func (s *auditPaginationStore) SearchAuditEventsPaged(query string, limit, offset int) ([]*store.AuditEvent, error) {
	s.lastLimit = limit
	s.lastOffset = offset
	return []*store.AuditEvent{}, nil
}

func (s *auditPaginationStore) CountAuditEvents() (int, error) {
	return 1, nil
}

func (s *auditPaginationStore) CountSearchAuditEvents(query string) (int, error) {
	return 1, nil
}

func (s *auditPaginationStore) ListAuditEvents() ([]*store.AuditEvent, error) {
	return []*store.AuditEvent{}, nil
}

func (s *auditPaginationStore) SearchAuditEvents(query string) ([]*store.AuditEvent, error) {
	return []*store.AuditEvent{}, nil
}

func (s *auditPaginationStore) AddAuditEvent(actor, targetUser, action, reason, ipAddress string) (*store.AuditEvent, error) {
	return &store.AuditEvent{}, nil
}

func (s *auditPaginationStore) AddComputer(serial, username, computerName string) (*store.Computer, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) UpsertComputer(serial, username, computerName string, lastCheckin time.Time) (*store.Computer, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) ListComputers() ([]*store.Computer, error) {
	return []*store.Computer{}, nil
}

func (s *auditPaginationStore) GetComputerByID(id int) (*store.Computer, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) GetComputerBySerial(serial string) (*store.Computer, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) AddSecret(computerID int, secretType, secret string, rotationRequired bool) (*store.Secret, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) ListSecretsByComputer(computerID int) ([]*store.Secret, error) {
	return []*store.Secret{}, nil
}

func (s *auditPaginationStore) GetSecretByID(id int) (*store.Secret, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) GetLatestSecretByComputerAndType(computerID int, secretType string) (*store.Secret, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) AddRequest(secretID int, requestingUser, reason string, approvedBy string, approved *bool) (*store.Request, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) ListRequestsBySecret(secretID int) ([]*store.Request, error) {
	return []*store.Request{}, nil
}

func (s *auditPaginationStore) ListOutstandingRequests() ([]*store.Request, error) {
	return []*store.Request{}, nil
}

func (s *auditPaginationStore) GetRequestByID(id int) (*store.Request, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) ApproveRequest(requestID int, approved bool, reason, approver string) (*store.Request, error) {
	return nil, store.ErrNotFound
}

func (s *auditPaginationStore) AddUser(username, passwordHash string, isStaff, canApprove, localLoginEnabled, mustResetPassword bool, authSource string) (*store.User, error) {
	return nil, nil
}

func (s *auditPaginationStore) GetUserByUsername(username string) (*store.User, error) {
	return &store.User{ID: 1, Username: username, IsStaff: true, LocalLoginEnabled: true}, nil
}

func (s *auditPaginationStore) ListUsers() ([]*store.User, error) {
	return []*store.User{}, nil
}

func (s *auditPaginationStore) GetUserByID(id int) (*store.User, error) {
	return &store.User{ID: id, Username: "user"}, nil
}

func (s *auditPaginationStore) UpdateUser(id int, username string, isStaff, canApprove, localLoginEnabled, mustResetPassword bool, authSource string) (*store.User, error) {
	return &store.User{ID: id, Username: username}, nil
}

func (s *auditPaginationStore) UpdateUserPassword(id int, passwordHash string, mustResetPassword bool) (*store.User, error) {
	return &store.User{ID: id, Username: "user"}, nil
}

func (s *auditPaginationStore) DeleteUser(id int) error {
	return nil
}

func (s *auditPaginationStore) CleanupRequests(approvedBefore time.Time) (int, error) {
	return 0, nil
}

func (s *auditPaginationStore) SetSecretRotationRequired(secretID int, rotationRequired bool) (*store.Secret, error) {
	return nil, store.ErrNotFound
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

func TestRetrieveMarksRotationRequired(t *testing.T) {
	codec := testCodec(t)
	sqliteStore := newTestSQLiteStore(t, codec)
	dataStore := &rotationTrackingStore{SQLiteStore: sqliteStore}
	server, sessionManager := newTestServerWithStore(t, dataStore)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := dataStore.AddUser("admin", passwordHash, true, true, true, false, "local")
	require.NoError(t, err)
	server.settings.RotateViewedSecrets = true
	require.True(t, server.settings.RotateViewedSecrets)
	computer, err := dataStore.AddComputer("SERIALROTATE", "user", "MacBook Pro")
	require.NoError(t, err)
	secret, err := dataStore.AddSecret(computer.ID, "recovery_key", "secret-value", false)
	require.NoError(t, err)
	initial, err := dataStore.GetSecretByID(secret.ID)
	require.NoError(t, err)
	require.False(t, initial.RotationRequired)
	approved := true
	req, err := dataStore.AddRequest(secret.ID, "admin", "Need access", "approver", &approved)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	retrieveReq := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/retrieve/"+intToString(req.ID)+"/", nil, "admin")
	serveProtected(server, rec, retrieveReq, server.handleRetrieve)
	require.Equal(t, http.StatusOK, rec.Code)
	require.True(t, dataStore.called)

	var rotation int
	row := sqliteStore.DB().QueryRow("SELECT rotation_required FROM secrets WHERE id = ?", secret.ID)
	require.NoError(t, row.Scan(&rotation))
	require.Equal(t, 1, rotation)

	updated, err := dataStore.GetSecretByID(secret.ID)
	require.NoError(t, err)
	require.True(t, updated.RotationRequired)
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

func TestUserPasswordResetLogsAuditEvent(t *testing.T) {
	codec := testCodec(t)
	sqliteStore := newTestSQLiteStore(t, codec)
	server, sessionManager := newTestServerWithStore(t, sqliteStore)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := sqliteStore.AddUser("admin", passwordHash, true, true, true, false, "local")
	require.NoError(t, err)
	target, err := sqliteStore.AddUser("reset", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("password", "newpassword")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/password/", form, "admin")
	req.RemoteAddr = "192.0.2.9:1234"
	serveProtected(server, rec, req, server.handleUserPassword)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	events, err := sqliteStore.ListAuditEvents()
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "admin", events[0].Actor)
	require.Equal(t, "reset", events[0].TargetUser)
	require.Equal(t, "password_reset", events[0].Action)
	require.Equal(t, "192.0.2.9", events[0].IPAddress)
}

func TestUserEditForceResetLogsAuditEvent(t *testing.T) {
	codec := testCodec(t)
	sqliteStore := newTestSQLiteStore(t, codec)
	server, sessionManager := newTestServerWithStore(t, sqliteStore)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := sqliteStore.AddUser("admin", passwordHash, true, true, true, false, "local")
	require.NoError(t, err)
	target, err := sqliteStore.AddUser("target", passwordHash, false, false, true, false, "local")
	require.NoError(t, err)

	form := url.Values{}
	form.Set("username", "target")
	form.Set("must_reset_password", "on")
	form.Set("local_login_enabled", "on")
	form.Set("auth_source", "local")
	rec := httptest.NewRecorder()
	req := newAuthenticatedFormRequest(t, server, sessionManager, http.MethodPost, "/admin/users/"+intToString(target.ID)+"/edit/", form, "admin")
	req.RemoteAddr = "198.51.100.10:9999"
	serveProtected(server, rec, req, server.handleUserEdit)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	events, err := sqliteStore.ListAuditEvents()
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "force_reset_enabled", events[0].Action)
	require.Equal(t, "198.51.100.10", events[0].IPAddress)
}

func TestIDFromPath(t *testing.T) {
	id, err := idFromPath("/info/", "/info/123/")
	require.NoError(t, err)
	require.Equal(t, 123, id)

	_, err = idFromPath("/info/", "/other/123/")
	require.Error(t, err)
}

func TestAuditLogSearch(t *testing.T) {
	codec := testCodec(t)
	sqliteStore := newTestSQLiteStore(t, codec)
	server, sessionManager := newTestServerWithStore(t, sqliteStore)
	passwordHash := hashPasswordForTest(t, "password")
	_, err := sqliteStore.AddUser("admin", passwordHash, true, true, true, false, "local")
	require.NoError(t, err)
	_, err = sqliteStore.AddAuditEvent("admin", "user1", "password_reset", "reason", "127.0.0.1")
	require.NoError(t, err)
	_, err = sqliteStore.AddAuditEvent("admin", "user2", "user_deleted", "", "127.0.0.1")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/admin/audit/?q=reset", nil, "admin")
	serveProtected(server, rec, req, server.handleAuditLog)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "password_reset")
	require.NotContains(t, rec.Body.String(), "user_deleted")
}

func TestAuditLogPaginationUsesPageParam(t *testing.T) {
	storeSpy := &auditPaginationStore{}
	server, sessionManager := newTestServerWithStore(t, storeSpy)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, sessionManager, http.MethodGet, "/admin/audit/?page=2", nil, "admin")
	serveProtected(server, rec, req, server.handleAuditLog)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 50, storeSpy.lastLimit)
	require.Equal(t, 50, storeSpy.lastOffset)
}

func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	require.Equal(t, "203.0.113.5", clientIP(req))

	req.Header.Set("X-Real-IP", "192.0.2.1")
	require.Equal(t, "192.0.2.1", clientIP(req))

	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9")
	require.Equal(t, "198.51.100.1", clientIP(req))
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
	events, err := memStore.ListAuditEvents()
	require.NoError(t, err)
	event, ok := findAuditEvent(events, "user_created")
	require.True(t, ok)
	require.Equal(t, "newuser", event.TargetUser)
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
	events, err := memStore.ListAuditEvents()
	require.NoError(t, err)
	_, ok := findAuditEvent(events, "user_updated")
	require.True(t, ok)
	_, ok = findAuditEvent(events, "force_reset_enabled")
	require.True(t, ok)
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
	events, err := memStore.ListAuditEvents()
	require.NoError(t, err)
	event, ok := findAuditEvent(events, "user_deleted")
	require.True(t, ok)
	require.Equal(t, "remove", event.TargetUser)
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

func findAuditEvent(events []*store.AuditEvent, action string) (*store.AuditEvent, bool) {
	for _, event := range events {
		if event.Action == action {
			return event, true
		}
	}
	return nil, false
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
