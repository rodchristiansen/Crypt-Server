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

	"crypt-server/internal/crypto"
	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

func newTestServer(t *testing.T) (*Server, *store.MemoryStore) {
	t.Helper()
	root := filepath.Join("..", "..")
	layout := filepath.Join(root, "web", "templates", "layouts", "base.html")
	pages := filepath.Join(root, "web", "templates", "pages")
	renderer := NewRenderer(layout, pages)
	codec := testCodec(t)
	memStore := store.NewMemoryStore(codec)
	logger := log.New(io.Discard, "", 0)
	server := NewServer(memStore, renderer, logger)
	return server, memStore
}

func TestHandleIndex(t *testing.T) {
	server, memStore := newTestServer(t)
	_, err := memStore.AddComputer("SERIAL1", "user", "Mac")
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	server.handleIndex(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Serial Number")
}

func TestHandleTableAjax(t *testing.T) {
	server, memStore := newTestServer(t)
	_, err := memStore.AddComputer("SERIAL2", "user", "iMac")
	require.NoError(t, err)

	payload := map[string]any{"draw": 1}
	payloadBytes, _ := json.Marshal(payload)
	query := url.Values{}
	query.Set("args", string(payloadBytes))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ajax/?"+query.Encode(), nil)
	server.handleTableAjax(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var data map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &data))
	require.Equal(t, float64(1), data["recordsTotal"])
}

func TestHandleNewComputerFlow(t *testing.T) {
	server, _ := newTestServer(t)
	form := url.Values{}
	form.Set("serial", "SERIAL3")
	form.Set("username", "user3")
	form.Set("computername", "MacBook Air")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/new/computer/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleNewComputer(rec, req)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Contains(t, rec.Header().Get("Location"), "/info/")
}

func TestRequestApproveRetrieveFlow(t *testing.T) {
	server, memStore := newTestServer(t)
	computer, err := memStore.AddComputer("SERIAL4", "user4", "MacBook Pro")
	require.NoError(t, err)
	secret, err := memStore.AddSecret(computer.ID, "recovery_key", "secret-value", false)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("reason_for_request", "Need access")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/request/"+intToString(secret.ID)+"/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.handleRequest(rec, req)

	require.Equal(t, http.StatusSeeOther, rec.Code)

	requests, err := memStore.ListRequestsBySecret(secret.ID)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	infoRec := httptest.NewRecorder()
	infoReq := httptest.NewRequest(http.MethodGet, "/info/secret/"+intToString(secret.ID)+"/", nil)
	server.handleSecretInfo(infoRec, infoReq)
	require.Contains(t, infoRec.Body.String(), "Retrieve Key")

	retrieveRec := httptest.NewRecorder()
	retrieveReq := httptest.NewRequest(http.MethodGet, "/retrieve/"+intToString(requests[0].ID)+"/", nil)
	server.handleRetrieve(retrieveRec, retrieveReq)
	require.Equal(t, http.StatusOK, retrieveRec.Code)
	require.Contains(t, retrieveRec.Body.String(), "class=\"letter\">s")
}

func TestHandleManageRequests(t *testing.T) {
	server, memStore := newTestServer(t)
	computer, err := memStore.AddComputer("SERIAL5", "user5", "Mac Mini")
	require.NoError(t, err)
	secret, err := memStore.AddSecret(computer.ID, "password", "secret", false)
	require.NoError(t, err)
	_, err = memStore.AddRequest(secret.ID, "user5", "Need access", "", nil)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/manage-requests/", nil)
	server.handleManageRequests(rec, req)

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
	server, memStore := newTestServer(t)
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
	server, _ := newTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/checkin/", nil)
	server.handleCheckin(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/verify/serial/type/", nil)
	server.handleVerify(rec, req)
	require.Equal(t, http.StatusNotImplemented, rec.Code)
}

func intToString(value int) string {
	return strconv.Itoa(value)
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
