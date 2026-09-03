package app

import (
	"net/http"

	"crypt-server/internal/store"
)

// APIPrefix is where the JSON API is mounted.
const APIPrefix = "/api/v1"

// apiRoutes builds the API route table. Handlers are wrapped in the scope they
// require, so the permission for an endpoint is visible next to its path.
func (s *Server) apiRoutes() http.Handler {
	router := newAPIRouter(APIPrefix)

	// Meta. Health and readiness are unauthenticated so a load balancer can
	// reach them.
	router.handle(http.MethodGet, "health", s.handleAPIHealth)
	router.handle(http.MethodGet, "ready", s.handleAPIReady)
	router.handle(http.MethodGet, "settings", s.requireScope(store.ScopeAdmin, s.handleAPISettings))
	router.handle(http.MethodGet, "stats", s.requireScope(store.ScopeComputersRead, s.handleAPIStats))
	router.handle(http.MethodGet, "metrics", s.requireScope(store.ScopeComputersRead, s.handleMetrics))

	// Escrow: the device surface.
	router.handle(http.MethodPost, "escrow", s.requireScope(store.ScopeEscrowWrite, s.handleAPIEscrow))
	router.handle(http.MethodGet, "escrow/status", s.requireScope(store.ScopeEscrowWrite, s.handleAPIEscrowStatus))
	router.handle(http.MethodPost, "escrow/rotation-complete", s.requireScope(store.ScopeEscrowWrite, s.handleAPIRotationComplete))

	// Computers.
	router.handle(http.MethodGet, "computers", s.requireScope(store.ScopeComputersRead, s.handleAPIListComputers))
	router.handle(http.MethodPost, "computers", s.requireScope(store.ScopeComputersWrite, s.handleAPICreateComputer))
	router.handle(http.MethodGet, "computers.csv", s.requireScope(store.ScopeComputersRead, s.handleAPIExportComputersCSV))
	router.handle(http.MethodGet, "computers/stale", s.requireScope(store.ScopeComputersRead, s.handleAPIStaleComputers))
	router.handle(http.MethodPost, "computers:bulk-delete", s.requireScope(store.ScopeComputersDelete, s.handleAPIBulkDeleteComputers))

	for _, prefix := range []string{"computers/{id}", "computers/by-serial/{serial}"} {
		router.handle(http.MethodGet, prefix, s.requireScope(store.ScopeComputersRead, s.handleAPIGetComputer))
		router.handle(http.MethodPatch, prefix, s.requireScope(store.ScopeComputersWrite, s.handleAPIPatchComputer))
		router.handle(http.MethodDelete, prefix, s.requireScope(store.ScopeComputersDelete, s.handleAPIDeleteComputer))
		router.handle(http.MethodGet, prefix+"/secrets", s.requireScope(store.ScopeSecretsRead, s.handleAPIComputerSecrets))
		router.handle(http.MethodPost, prefix+"/secrets", s.requireScope(store.ScopeAdmin, s.handleAPIAddComputerSecret))
		router.handle(http.MethodGet, prefix+"/requests", s.requireScope(store.ScopeRequestsRead, s.handleAPIComputerRequests))
		router.handle(http.MethodGet, prefix+"/audit", s.requireScope(store.ScopeAuditRead, s.handleAPIComputerAudit))
	}

	// Secrets. Metadata is readable; the value has one scope of its own.
	router.handle(http.MethodGet, "secrets", s.requireScope(store.ScopeSecretsRead, s.handleAPIListSecrets))
	router.handle(http.MethodGet, "secrets/{id}", s.requireScope(store.ScopeSecretsRead, s.handleAPIGetSecret))
	router.handle(http.MethodGet, "secrets/{id}/value", s.requireScope(store.ScopeSecretsReveal, s.handleAPIRevealSecret))
	router.handle(http.MethodPost, "secrets/{id}/rotation", s.requireScope(store.ScopeSecretsRotate, s.handleAPISetSecretRotation))
	router.handle(http.MethodDelete, "secrets/{id}", s.requireScope(store.ScopeAdmin, s.handleAPIDeleteSecret))

	// Requests: the approval workflow.
	router.handle(http.MethodGet, "requests", s.requireScope(store.ScopeRequestsRead, s.handleAPIListRequests))
	router.handle(http.MethodPost, "requests", s.requireScope(store.ScopeRequestsWrite, s.handleAPICreateRequest))
	router.handle(http.MethodGet, "requests/{id}", s.requireScope(store.ScopeRequestsRead, s.handleAPIGetRequest))
	router.handle(http.MethodPost, "requests/{id}/approve", s.requireScope(store.ScopeRequestsApprove, s.handleAPIApproveRequest))
	router.handle(http.MethodPost, "requests/{id}/deny", s.requireScope(store.ScopeRequestsApprove, s.handleAPIDenyRequest))
	router.handle(http.MethodPost, "requests/{id}/retrieve", s.requireScope(store.ScopeRequestsRead, s.handleAPIRetrieveRequest))
	router.handle(http.MethodDelete, "requests/{id}", s.requireScope(store.ScopeRequestsWrite, s.handleAPICancelRequest))

	// Users.
	router.handle(http.MethodGet, "users/me", s.requireAuthenticated(s.handleAPIMe))
	router.handle(http.MethodPost, "users/me/password", s.requireAuthenticated(s.handleAPIChangeOwnPassword))
	router.handle(http.MethodGet, "users", s.requireScope(store.ScopeUsersRead, s.handleAPIListUsers))
	router.handle(http.MethodPost, "users", s.requireScope(store.ScopeUsersWrite, s.handleAPICreateUser))
	router.handle(http.MethodGet, "users/{id}", s.requireScope(store.ScopeUsersRead, s.handleAPIGetUser))
	router.handle(http.MethodPatch, "users/{id}", s.requireScope(store.ScopeUsersWrite, s.handleAPIPatchUser))
	router.handle(http.MethodDelete, "users/{id}", s.requireScope(store.ScopeUsersWrite, s.handleAPIDeleteUser))
	router.handle(http.MethodPost, "users/{id}/password", s.requireScope(store.ScopeUsersWrite, s.handleAPIAdminSetPassword))
	router.handle(http.MethodPost, "users/{id}/sessions:revoke", s.requireScope(store.ScopeUsersWrite, s.handleAPIRevokeUserSessions))

	// Tokens.
	router.handle(http.MethodGet, "tokens", s.requireScope(store.ScopeAdmin, s.handleAPIListTokens))
	router.handle(http.MethodPost, "tokens", s.requireScope(store.ScopeAdmin, s.handleAPICreateToken))
	router.handle(http.MethodGet, "tokens/{id}", s.requireScope(store.ScopeAdmin, s.handleAPIGetToken))
	router.handle(http.MethodDelete, "tokens/{id}", s.requireScope(store.ScopeAdmin, s.handleAPIRevokeToken))
	router.handle(http.MethodPost, "tokens/{id}/rotate", s.requireScope(store.ScopeAdmin, s.handleAPIRotateToken))

	// Audit.
	router.handle(http.MethodGet, "audit", s.requireScope(store.ScopeAuditRead, s.handleAPIAudit))
	router.handle(http.MethodGet, "audit.csv", s.requireScope(store.ScopeAuditRead, s.handleAPIAuditCSV))

	// Webhooks.
	router.handle(http.MethodGet, "webhooks", s.requireScope(store.ScopeAdmin, s.handleAPIListWebhooks))
	router.handle(http.MethodPost, "webhooks", s.requireScope(store.ScopeAdmin, s.handleAPICreateWebhook))
	router.handle(http.MethodGet, "webhooks/{id}", s.requireScope(store.ScopeAdmin, s.handleAPIGetWebhook))
	router.handle(http.MethodPatch, "webhooks/{id}", s.requireScope(store.ScopeAdmin, s.handleAPIPatchWebhook))
	router.handle(http.MethodDelete, "webhooks/{id}", s.requireScope(store.ScopeAdmin, s.handleAPIDeleteWebhook))
	router.handle(http.MethodPost, "webhooks/{id}/test", s.requireScope(store.ScopeAdmin, s.handleAPITestWebhook))
	router.handle(http.MethodGet, "webhooks/{id}/deliveries", s.requireScope(store.ScopeAdmin, s.handleAPIWebhookDeliveries))

	// Maintenance.
	router.handle(http.MethodPost, "maintenance/cleanup-requests", s.requireScope(store.ScopeAdmin, s.handleAPICleanupRequests))

	return router
}
