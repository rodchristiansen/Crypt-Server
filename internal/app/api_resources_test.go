package app

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"crypt-server/internal/store"
	"github.com/stretchr/testify/require"
)

func TestAPIEscrowCreatesComputerAndSecret(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", token, escrowRequest{
		Serial:       testSerialA,
		Username:     "someone",
		ComputerName: "a-mac",
		Secret:       "AAAA-BBBB-CCCC",
		Platform:     "macos",
		OSVersion:    "26.1",
		AgentVersion: "6.0.1",
	})

	requireStatus(t, recorder, http.StatusCreated)
	var body escrowResponse
	decodeAPIBody(t, recorder, &body)
	require.True(t, body.NewSecretEscrowed)
	require.Equal(t, testSerialA, body.Serial)

	computer, err := dataStore.GetComputerBySerial(testSerialA)
	require.NoError(t, err)
	require.Equal(t, "macos", computer.Platform)
	require.Equal(t, "6.0.1", computer.AgentVersion)
}

func TestAPIEscrowSecondCallIsNotNew(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	body := escrowRequest{Serial: testSerialA, Username: "someone", Secret: "AAAA-BBBB-CCCC"}

	first := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", token, body)
	requireStatus(t, first, http.StatusCreated)
	second := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", token, body)
	requireStatus(t, second, http.StatusCreated)

	var decoded escrowResponse
	decodeAPIBody(t, second, &decoded)
	require.False(t, decoded.NewSecretEscrowed)
}

func TestAPIEscrowRejectsMissingFields(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/escrow", token, escrowRequest{Username: "x", Secret: "y"})

	requireStatus(t, recorder, http.StatusBadRequest)
	require.Equal(t, "serial_required", apiErrorCode(t, recorder))
}

func TestAPIEscrowStatusReportsEscrowState(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	seedComputerWithSecret(t, dataStore, testSerialA, "AAAA-BBBB")

	found := apiRequest(t, server, http.MethodGet,
		"/api/v1/escrow/status?serial="+testSerialA+"&secret_type=recovery_key", token, nil)
	requireStatus(t, found, http.StatusOK)
	var body escrowStatusResponse
	decodeAPIBody(t, found, &body)
	require.True(t, body.Escrowed)
	require.NotNil(t, body.DateEscrowed)

	missing := apiRequest(t, server, http.MethodGet, "/api/v1/escrow/status?serial="+testSerialB, token, nil)
	requireStatus(t, missing, http.StatusOK)
	decodeAPIBody(t, missing, &body)
	require.False(t, body.Escrowed)
}

func TestAPIEscrowStatusNeverReturnsTheSecret(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/escrow/status?serial="+testSerialA, token, nil)

	require.NotContains(t, recorder.Body.String(), "SENSITIVE-VALUE")
}

func TestAPIRotationCompleteClearsTheFlag(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindDevice, store.ScopeEscrowWrite)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA-BBBB")
	_, err := dataStore.SetSecretRotationRequired(secret.ID, true)
	require.NoError(t, err)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/escrow/rotation-complete", token,
		rotationCompleteRequest{Serial: testSerialA, SecretType: "recovery_key"})

	requireStatus(t, recorder, http.StatusOK)
	updated, err := dataStore.GetSecretByID(secret.ID)
	require.NoError(t, err)
	require.False(t, updated.RotationRequired)
}

func TestAPIListComputersFiltersAndPaginates(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)
	seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")
	seedComputerWithSecret(t, dataStore, testSerialB, "BBBB")
	_, err := dataStore.UpsertComputer(testSerialC, "user", "no-secret", time.Now())
	require.NoError(t, err)

	all := apiRequest(t, server, http.MethodGet, "/api/v1/computers", token, nil)
	requireStatus(t, all, http.StatusOK)
	var listing struct {
		Count   int            `json:"count"`
		PerPage int            `json:"per_page"`
		Results []computerView `json:"results"`
	}
	decodeAPIBody(t, all, &listing)
	require.Equal(t, 3, listing.Count)

	unescrowed := apiRequest(t, server, http.MethodGet, "/api/v1/computers?escrowed=false", token, nil)
	decodeAPIBody(t, unescrowed, &listing)
	require.Equal(t, 1, listing.Count)
	require.Equal(t, testSerialC, listing.Results[0].Serial)

	searched := apiRequest(t, server, http.MethodGet, "/api/v1/computers?search=AAA", token, nil)
	decodeAPIBody(t, searched, &listing)
	require.Equal(t, 1, listing.Count)

	paged := apiRequest(t, server, http.MethodGet, "/api/v1/computers?per_page=2&page=2", token, nil)
	decodeAPIBody(t, paged, &listing)
	require.Equal(t, 3, listing.Count)
	require.Len(t, listing.Results, 1)
}

func TestAPIListComputersNeverReturnsSecrets(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)
	seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")

	listing := apiRequest(t, server, http.MethodGet, "/api/v1/computers", token, nil)
	detail := apiRequest(t, server, http.MethodGet, "/api/v1/computers/by-serial/"+testSerialA, token, nil)

	require.NotContains(t, listing.Body.String(), "SENSITIVE-VALUE")
	require.NotContains(t, detail.Body.String(), "SENSITIVE-VALUE")
}

func TestAPIGetComputerBySerialAndID(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead, store.ScopeSecretsRead)
	computer, _ := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	bySerial := apiRequest(t, server, http.MethodGet, "/api/v1/computers/by-serial/"+testSerialA, token, nil)
	byID := apiRequest(t, server, http.MethodGet, "/api/v1/computers/"+strconv.Itoa(computer.ID), token, nil)

	requireStatus(t, bySerial, http.StatusOK)
	requireStatus(t, byID, http.StatusOK)
	var view computerView
	decodeAPIBody(t, byID, &view)
	require.Len(t, view.Secrets, 1)
	require.NotNil(t, view.SecretsCount)
	require.Equal(t, 1, *view.SecretsCount)
}

func TestAPIGetComputerNotFound(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/computers/9999", token, nil)

	requireStatus(t, recorder, http.StatusNotFound)
	require.Equal(t, "computer_not_found", apiErrorCode(t, recorder))
}

func TestAPIPatchComputer(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersWrite)
	computer, _ := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")
	newName := "renamed"

	recorder := apiRequest(t, server, http.MethodPatch, "/api/v1/computers/"+strconv.Itoa(computer.ID), token,
		patchComputerRequest{ComputerName: &newName})

	requireStatus(t, recorder, http.StatusOK)
	updated, err := dataStore.GetComputerByID(computer.ID)
	require.NoError(t, err)
	require.Equal(t, "renamed", updated.ComputerName)
}

func TestAPIDeleteComputerBlockedByPendingRequest(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersDelete)
	computer, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")
	_, err := dataStore.AddRequest(secret.ID, "someone", "because", "", nil)
	require.NoError(t, err)

	blocked := apiRequest(t, server, http.MethodDelete, "/api/v1/computers/"+strconv.Itoa(computer.ID), token, nil)
	requireStatus(t, blocked, http.StatusConflict)
	require.Equal(t, "pending_requests_exist", apiErrorCode(t, blocked))

	forced := apiRequest(t, server, http.MethodDelete, "/api/v1/computers/"+strconv.Itoa(computer.ID)+"?force=true", token, nil)
	requireStatus(t, forced, http.StatusNoContent)
	_, err = dataStore.GetComputerByID(computer.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestAPIBulkDeleteReportsPerSerial(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersDelete)
	seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/computers:bulk-delete", token,
		bulkDeleteRequest{Serials: []string{testSerialA, testSerialB}})

	requireStatus(t, recorder, http.StatusOK)
	var body struct {
		Results []bulkDeleteResult `json:"results"`
	}
	decodeAPIBody(t, recorder, &body)
	require.Len(t, body.Results, 2)
	require.Equal(t, "deleted", body.Results[0].Status)
	require.Equal(t, "not_found", body.Results[1].Status)
}

func TestAPISecretValueRequiresRevealScope(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	readOnly := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeSecretsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")

	denied := apiRequest(t, server, http.MethodGet, "/api/v1/secrets/"+strconv.Itoa(secret.ID)+"/value", readOnly, nil)
	requireStatus(t, denied, http.StatusForbidden)

	metadata := apiRequest(t, server, http.MethodGet, "/api/v1/secrets/"+strconv.Itoa(secret.ID), readOnly, nil)
	requireStatus(t, metadata, http.StatusOK)
	require.NotContains(t, metadata.Body.String(), "SENSITIVE-VALUE")
}

func TestAPISecretValueRevealIsAudited(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeSecretsReveal)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")

	recorder := apiRequest(t, server, http.MethodGet,
		"/api/v1/secrets/"+strconv.Itoa(secret.ID)+"/value?reason=incident", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	var body secretValueResponse
	decodeAPIBody(t, recorder, &body)
	require.Equal(t, "SENSITIVE-VALUE", body.Secret)
	require.True(t, body.BreakGlass)

	events, err := dataStore.ListAuditEventsFiltered(store.AuditFilter{Action: EventSecretViewed})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "incident", events[0].Reason)
	require.Contains(t, events[0].Metadata, "break_glass")
}

func TestAPIRevealFlagsRotationWhenConfigured(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.settings.RotateViewedSecrets = true
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeSecretsReveal)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/secrets/"+strconv.Itoa(secret.ID)+"/value", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	updated, err := dataStore.GetSecretByID(secret.ID)
	require.NoError(t, err)
	require.True(t, updated.RotationRequired)
}

func TestAPIRequestWorkflow(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "requester", false, false)
	seedUser(t, dataStore, "approver", false, true)
	requesterToken := mintUserToken(t, dataStore, "requester", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	approverToken := mintUserToken(t, dataStore, "approver", store.ScopeRequestsApprove, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", requesterToken,
		createRequestBody{SecretID: secret.ID, Reason: "user locked out"})
	requireStatus(t, created, http.StatusCreated)
	var request requestView
	decodeAPIBody(t, created, &request)
	require.Equal(t, "pending", request.Status)

	tooEarly := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/retrieve", requesterToken, nil)
	requireStatus(t, tooEarly, http.StatusForbidden)
	require.Equal(t, "request_not_approved", apiErrorCode(t, tooEarly))

	approved := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/approve", approverToken, decisionBody{Reason: "verified by phone"})
	requireStatus(t, approved, http.StatusOK)

	retrieved := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/retrieve", requesterToken, nil)
	requireStatus(t, retrieved, http.StatusOK)
	var payload retrieveResponse
	decodeAPIBody(t, retrieved, &payload)
	require.Equal(t, "SENSITIVE-VALUE", payload.Secret)
}

func TestAPIRequesterCannotApproveOwnRequestByDefault(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "approver", false, true)
	token := mintUserToken(t, dataStore, "approver", store.ScopeRequestsWrite, store.ScopeRequestsRead, store.ScopeRequestsApprove)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", token,
		createRequestBody{SecretID: secret.ID, Reason: "need it"})
	requireStatus(t, created, http.StatusCreated)
	var request requestView
	decodeAPIBody(t, created, &request)
	require.Equal(t, "pending", request.Status)

	recorder := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/approve", token, decisionBody{Reason: "mine"})

	requireStatus(t, recorder, http.StatusForbidden)
	require.Equal(t, "cannot_approve", apiErrorCode(t, recorder))
}

func TestAPISelfApprovalWhenApproveOwnIsSet(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	server.settings.ApproveOwn = true
	seedUser(t, dataStore, "approver", false, true)
	token := mintUserToken(t, dataStore, "approver", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", token,
		createRequestBody{SecretID: secret.ID, Reason: "need it"})

	requireStatus(t, created, http.StatusCreated)
	var request requestView
	decodeAPIBody(t, created, &request)
	require.Equal(t, "approved", request.Status)
}

func TestAPIDenyThenRetrieveIsRefused(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "requester", false, false)
	seedUser(t, dataStore, "approver", false, true)
	requesterToken := mintUserToken(t, dataStore, "requester", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	approverToken := mintUserToken(t, dataStore, "approver", store.ScopeRequestsApprove, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", requesterToken,
		createRequestBody{SecretID: secret.ID, Reason: "curious"})
	var request requestView
	decodeAPIBody(t, created, &request)

	denied := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/deny", approverToken, decisionBody{Reason: "no business need"})
	requireStatus(t, denied, http.StatusOK)

	retrieve := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/retrieve", requesterToken, nil)
	requireStatus(t, retrieve, http.StatusForbidden)
}

func TestAPIDecidingTwiceConflicts(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "requester", false, false)
	seedUser(t, dataStore, "approver", false, true)
	requesterToken := mintUserToken(t, dataStore, "requester", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	approverToken := mintUserToken(t, dataStore, "approver", store.ScopeRequestsApprove, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", requesterToken,
		createRequestBody{SecretID: secret.ID, Reason: "need it"})
	var request requestView
	decodeAPIBody(t, created, &request)

	first := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/approve", approverToken, decisionBody{Reason: "ok"})
	requireStatus(t, first, http.StatusOK)

	second := apiRequest(t, server, http.MethodPost,
		"/api/v1/requests/"+strconv.Itoa(request.ID)+"/approve", approverToken, decisionBody{Reason: "ok again"})
	requireStatus(t, second, http.StatusConflict)
	require.Equal(t, "request_already_decided", apiErrorCode(t, second))
}

func TestAPICancelOwnPendingRequest(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "requester", false, false)
	seedUser(t, dataStore, "other", false, false)
	requesterToken := mintUserToken(t, dataStore, "requester", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	otherToken := mintUserToken(t, dataStore, "other", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	created := apiRequest(t, server, http.MethodPost, "/api/v1/requests", requesterToken,
		createRequestBody{SecretID: secret.ID, Reason: "mistake"})
	var request requestView
	decodeAPIBody(t, created, &request)

	forbidden := apiRequest(t, server, http.MethodDelete, "/api/v1/requests/"+strconv.Itoa(request.ID), otherToken, nil)
	requireStatus(t, forbidden, http.StatusForbidden)

	cancelled := apiRequest(t, server, http.MethodDelete, "/api/v1/requests/"+strconv.Itoa(request.ID), requesterToken, nil)
	requireStatus(t, cancelled, http.StatusNoContent)

	_, err := dataStore.GetRequestByID(request.ID)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestAPIListRequestsFiltersByStatusAndOwner(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	seedUser(t, dataStore, "requester", false, false)
	token := mintUserToken(t, dataStore, "requester", store.ScopeRequestsWrite, store.ScopeRequestsRead)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")
	_, err := dataStore.AddRequest(secret.ID, "requester", "one", "", nil)
	require.NoError(t, err)
	_, err = dataStore.AddRequest(secret.ID, "somebody-else", "two", "", nil)
	require.NoError(t, err)

	var listing struct {
		Count   int           `json:"count"`
		Results []requestView `json:"results"`
	}
	pending := apiRequest(t, server, http.MethodGet, "/api/v1/requests?status=pending", token, nil)
	decodeAPIBody(t, pending, &listing)
	require.Equal(t, 2, listing.Count)

	mine := apiRequest(t, server, http.MethodGet, "/api/v1/requests?mine=true", token, nil)
	decodeAPIBody(t, mine, &listing)
	require.Equal(t, 1, listing.Count)
	require.Equal(t, "requester", listing.Results[0].RequestingUser)
}

func TestAPIUserAdministration(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeUsersRead, store.ScopeUsersWrite)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/users", token, createUserBody{
		Username:          "newcomer",
		Password:          "a-sufficiently-long-password",
		LocalLoginEnabled: true,
		CanApprove:        true,
	})
	requireStatus(t, created, http.StatusCreated)
	var user userView
	decodeAPIBody(t, created, &user)
	require.True(t, user.CanApprove)
	require.NotContains(t, created.Body.String(), "a-sufficiently-long-password")

	duplicate := apiRequest(t, server, http.MethodPost, "/api/v1/users", token, createUserBody{
		Username: "newcomer", Password: "a-sufficiently-long-password", LocalLoginEnabled: true,
	})
	requireStatus(t, duplicate, http.StatusConflict)

	staff := true
	patched := apiRequest(t, server, http.MethodPatch, "/api/v1/users/"+strconv.Itoa(user.ID), token,
		patchUserBody{IsStaff: &staff})
	requireStatus(t, patched, http.StatusOK)

	deleted := apiRequest(t, server, http.MethodDelete, "/api/v1/users/"+strconv.Itoa(user.ID), token, nil)
	requireStatus(t, deleted, http.StatusNoContent)
}

func TestAPICreateUserRejectsShortPassword(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeUsersWrite)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/users", token, createUserBody{
		Username: "shorty", Password: "short", LocalLoginEnabled: true,
	})

	requireStatus(t, recorder, http.StatusBadRequest)
	require.Equal(t, "password_too_short", apiErrorCode(t, recorder))
}

func TestAPIAdminPasswordResetIsAudited(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeUsersWrite)
	user := seedUser(t, dataStore, "target", false, false)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/users/"+strconv.Itoa(user.ID)+"/password", token,
		adminPasswordBody{Password: "a-sufficiently-long-password", MustResetPassword: true, Reason: "offboarding"})

	requireStatus(t, recorder, http.StatusOK)
	events, err := dataStore.ListAuditEventsFiltered(store.AuditFilter{Action: EventUserPasswordReset})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "target", events[0].TargetUser)
	require.Equal(t, "offboarding", events[0].Reason)
}

func TestAPIRevokeUserSessions(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeUsersWrite)
	user := seedUser(t, dataStore, "leaver", false, false)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/users/"+strconv.Itoa(user.ID)+"/sessions:revoke", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	revokedAt, err := dataStore.SessionsRevokedAt("leaver")
	require.NoError(t, err)
	require.NotNil(t, revokedAt)
}

func TestAPITokenLifecycle(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	created := apiRequest(t, server, http.MethodPost, "/api/v1/tokens", admin, createTokenBody{
		Name:   "reportmate",
		Kind:   store.TokenKindService,
		Scopes: []string{store.ScopeComputersRead},
	})
	requireStatus(t, created, http.StatusCreated)
	var body createTokenResponse
	decodeAPIBody(t, created, &body)
	require.NotEmpty(t, body.Secret)
	require.True(t, body.Token.Active)

	// The minted token works for its scope and nothing more.
	allowed := apiRequest(t, server, http.MethodGet, "/api/v1/computers", body.Secret, nil)
	requireStatus(t, allowed, http.StatusOK)

	listed := apiRequest(t, server, http.MethodGet, "/api/v1/tokens", admin, nil)
	requireStatus(t, listed, http.StatusOK)
	require.NotContains(t, listed.Body.String(), body.Secret)

	revoked := apiRequest(t, server, http.MethodDelete, "/api/v1/tokens/"+strconv.Itoa(body.Token.ID), admin, nil)
	requireStatus(t, revoked, http.StatusNoContent)

	afterRevoke := apiRequest(t, server, http.MethodGet, "/api/v1/computers", body.Secret, nil)
	requireStatus(t, afterRevoke, http.StatusUnauthorized)
}

func TestAPICreateTokenRejectsDeviceRevealScope(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	admin := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/tokens", admin, createTokenBody{
		Name:   "sneaky-device",
		Kind:   store.TokenKindDevice,
		Scopes: []string{store.ScopeSecretsReveal},
	})

	requireStatus(t, recorder, http.StatusBadRequest)
	require.Equal(t, "invalid_scopes", apiErrorCode(t, recorder))
}

func TestAPIStatsCountsTheFleet(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)
	seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")
	_, err := dataStore.UpsertComputer(testSerialB, "user", "bare", time.Now())
	require.NoError(t, err)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/stats", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	var stats store.Stats
	decodeAPIBody(t, recorder, &stats)
	require.Equal(t, 2, stats.ComputersTotal)
	require.Equal(t, 1, stats.NeverEscrowed)
	require.Equal(t, 1, stats.EscrowedByType["recovery_key"])
}

func TestAPIMetricsRendersPrometheusText(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)
	seedComputerWithSecret(t, dataStore, testSerialA, "AAAA")

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/metrics", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	require.Contains(t, recorder.Body.String(), "crypt_computers_total 1")
	require.Contains(t, recorder.Body.String(), `crypt_computers_escrowed{secret_type="recovery_key"} 1`)
}

func TestAPIComputersCSVExcludesSecrets(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeComputersRead)
	seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/computers.csv", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	require.Contains(t, recorder.Header().Get("Content-Type"), "text/csv")
	require.Contains(t, recorder.Body.String(), testSerialA)
	require.NotContains(t, recorder.Body.String(), "SENSITIVE-VALUE")
}

func TestAPIAuditSearchAndCSV(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)
	_, secret := seedComputerWithSecret(t, dataStore, testSerialA, "SENSITIVE-VALUE")
	reveal := apiRequest(t, server, http.MethodGet, "/api/v1/secrets/"+strconv.Itoa(secret.ID)+"/value", token, nil)
	requireStatus(t, reveal, http.StatusOK)

	listing := apiRequest(t, server, http.MethodGet, "/api/v1/audit?action="+EventSecretViewed, token, nil)
	requireStatus(t, listing, http.StatusOK)
	var body struct {
		Count int `json:"count"`
	}
	decodeAPIBody(t, listing, &body)
	require.Equal(t, 1, body.Count)

	csv := apiRequest(t, server, http.MethodGet, "/api/v1/audit.csv", token, nil)
	requireStatus(t, csv, http.StatusOK)
	require.NotContains(t, csv.Body.String(), "SENSITIVE-VALUE")
}

func TestAPICleanupRequestsSweep(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	recorder := apiRequest(t, server, http.MethodPost, "/api/v1/maintenance/cleanup-requests", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	var body map[string]any
	decodeAPIBody(t, recorder, &body)
	require.Contains(t, body, "cleaned")
}

func TestAPISettingsReportsPolicy(t *testing.T) {
	server, dataStore := newAPITestServer(t)
	token := mintTestToken(t, dataStore, store.TokenKindService, store.ScopeAdmin)

	recorder := apiRequest(t, server, http.MethodGet, "/api/v1/settings", token, nil)

	requireStatus(t, recorder, http.StatusOK)
	var body map[string]any
	decodeAPIBody(t, recorder, &body)
	require.Equal(t, false, body["approve_own"])
	require.Equal(t, float64(7), body["request_retention_days"])
}
