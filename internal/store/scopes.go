package store

// Token kinds. A device token belongs to a machine, a service token to
// automation, and a user token acts as the user it was minted for.
const (
	TokenKindDevice  = "device"
	TokenKindService = "service"
	TokenKindUser    = "user"
)

// API scopes. ScopeAdmin implies every other scope.
const (
	ScopeEscrowWrite     = "escrow:write"
	ScopeComputersRead   = "computers:read"
	ScopeComputersWrite  = "computers:write"
	ScopeComputersDelete = "computers:delete"
	ScopeSecretsRead     = "secrets:read"
	ScopeSecretsRotate   = "secrets:rotate"
	ScopeSecretsReveal   = "secrets:reveal"
	ScopeRequestsRead    = "requests:read"
	ScopeRequestsWrite   = "requests:write"
	ScopeRequestsApprove = "requests:approve"
	ScopeUsersRead       = "users:read"
	ScopeUsersWrite      = "users:write"
	ScopeAuditRead       = "audit:read"
	ScopeAdmin           = "admin"
)

// AllScopes lists every scope the server understands.
var AllScopes = []string{
	ScopeEscrowWrite,
	ScopeComputersRead,
	ScopeComputersWrite,
	ScopeComputersDelete,
	ScopeSecretsRead,
	ScopeSecretsRotate,
	ScopeSecretsReveal,
	ScopeRequestsRead,
	ScopeRequestsWrite,
	ScopeRequestsApprove,
	ScopeUsersRead,
	ScopeUsersWrite,
	ScopeAuditRead,
	ScopeAdmin,
}

// deviceForbiddenScopes are scopes a device token may never hold. A machine
// escrows its own secret; it never reads one back.
var deviceForbiddenScopes = map[string]bool{
	ScopeSecretsReveal:   true,
	ScopeSecretsRead:     true,
	ScopeAdmin:           true,
	ScopeUsersRead:       true,
	ScopeUsersWrite:      true,
	ScopeAuditRead:       true,
	ScopeRequestsApprove: true,
	ScopeComputersDelete: true,
}

// IsKnownScope reports whether the scope is one the server understands.
func IsKnownScope(scope string) bool {
	for _, known := range AllScopes {
		if known == scope {
			return true
		}
	}
	return false
}

// ScopeAllowedForKind reports whether a token of the given kind may hold the
// scope. The server rejects a forbidden grant rather than silently dropping it.
func ScopeAllowedForKind(kind, scope string) bool {
	if kind != TokenKindDevice {
		return true
	}
	return !deviceForbiddenScopes[scope]
}
