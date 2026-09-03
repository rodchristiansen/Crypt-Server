package app

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"crypt-server/internal/store"
)

// Principal is the authenticated caller behind an API request. It is either a
// device, a service integration, or a person acting through a session cookie
// or a personal access token.
type Principal struct {
	Kind              string
	Username          string
	Scopes            []string
	TokenID           int
	TokenName         string
	IsStaff           bool
	CanApprove        bool
	LocalLoginEnabled bool
	ViaSession        bool
}

// Has reports whether the principal carries the scope.
func (p *Principal) Has(scope string) bool {
	if p == nil {
		return false
	}
	for _, granted := range p.Scopes {
		if granted == scope || granted == store.ScopeAdmin {
			return true
		}
	}
	return false
}

// Actor names the principal for audit events.
func (p *Principal) Actor() string {
	if p == nil {
		return "anonymous"
	}
	if p.Username != "" {
		return p.Username
	}
	if p.TokenName != "" {
		return "token:" + p.TokenName
	}
	return p.Kind
}

// sessionScopes derives the scopes a signed-in person holds from their
// permission flags, mirroring what the HTML UI already lets them do.
//
// secrets:reveal is deliberately absent: a person reads a secret by raising a
// request and having it approved, not by holding a scope.
func sessionScopes(user *User) []string {
	scopes := []string{
		store.ScopeComputersRead,
		store.ScopeSecretsRead,
		store.ScopeRequestsRead,
		store.ScopeRequestsWrite,
	}
	if user.CanApprove {
		scopes = append(scopes, store.ScopeRequestsApprove)
	}
	if user.IsStaff {
		scopes = append(scopes,
			store.ScopeComputersWrite,
			store.ScopeComputersDelete,
			store.ScopeSecretsRotate,
			store.ScopeUsersRead,
			store.ScopeUsersWrite,
			store.ScopeAuditRead,
			store.ScopeAdmin,
		)
	}
	return scopes
}

// intersectScopes narrows a token's scopes to those its owner actually holds,
// so a personal access token can never exceed the person who minted it.
func intersectScopes(tokenScopes, userScopes []string) []string {
	allowed := map[string]bool{}
	for _, scope := range userScopes {
		allowed[scope] = true
	}
	granted := make([]string, 0, len(tokenScopes))
	for _, scope := range tokenScopes {
		if scope == store.ScopeAdmin {
			if allowed[store.ScopeAdmin] {
				granted = append(granted, scope)
			}
			continue
		}
		if allowed[scope] || allowed[store.ScopeAdmin] {
			granted = append(granted, scope)
		}
	}
	return granted
}

// presentedToken extracts a credential from either the Authorization header or
// the X-API-Key header. X-API-Key is accepted so deployments already using the
// shared-key middleware keep working through the cutover.
func presentedToken(r *http.Request) string {
	if header := strings.TrimSpace(r.Header.Get("Authorization")); header != "" {
		if strings.HasPrefix(strings.ToLower(header), "bearer ") {
			return strings.TrimSpace(header[len("bearer "):])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// authenticate resolves the caller behind a request. It returns nil when no
// usable credential was presented.
func (s *Server) authenticate(r *http.Request) *Principal {
	if presented := presentedToken(r); presented != "" {
		if principal := s.principalFromToken(r, presented); principal != nil {
			return principal
		}
		return nil
	}
	if user := s.currentUser(r); user.IsAuthenticated {
		return &Principal{
			Kind:              store.TokenKindUser,
			Username:          user.Username,
			Scopes:            sessionScopes(&user),
			IsStaff:           user.IsStaff,
			CanApprove:        user.CanApprove,
			LocalLoginEnabled: user.LocalLoginEnabled,
			ViaSession:        true,
		}
	}
	return nil
}

// principalFromToken validates a presented token string.
func (s *Server) principalFromToken(r *http.Request, presented string) *Principal {
	// The legacy shared key grants escrow access only. It exists so an estate
	// running CRYPT_API_KEY against /checkin/ can adopt /api/v1/escrow without
	// minting tokens first.
	if s.settings.LegacyAPIKey != "" &&
		subtle.ConstantTimeCompare([]byte(presented), []byte(s.settings.LegacyAPIKey)) == 1 {
		return &Principal{
			Kind:      store.TokenKindDevice,
			TokenName: "legacy-shared-key",
			Scopes:    []string{store.ScopeEscrowWrite},
		}
	}

	prefix, secret, err := splitToken(presented)
	if err != nil {
		return nil
	}
	token, err := s.store.GetAPITokenByPrefix(prefix)
	if err != nil {
		return nil
	}
	if !verifyTokenSecret(secret, token.TokenHash) {
		return nil
	}
	now := time.Now()
	if !token.Active(now) {
		return nil
	}
	if err := s.store.TouchAPIToken(token.ID, now, clientIP(r)); err != nil {
		s.logger.Printf("api: touch token %d failed: %v", token.ID, err)
	}

	principal := &Principal{
		Kind:      token.Kind,
		Username:  token.Username,
		Scopes:    token.Scopes,
		TokenID:   token.ID,
		TokenName: token.Name,
	}
	if token.Kind == store.TokenKindUser && token.Username != "" {
		owner, err := s.store.GetUserByUsername(token.Username)
		if err != nil {
			return nil
		}
		principal.IsStaff = owner.IsStaff
		principal.CanApprove = owner.CanApprove
		principal.LocalLoginEnabled = owner.LocalLoginEnabled
		principal.Scopes = intersectScopes(token.Scopes, sessionScopes(&User{
			Username:          owner.Username,
			IsStaff:           owner.IsStaff,
			CanApprove:        owner.CanApprove,
			LocalLoginEnabled: owner.LocalLoginEnabled,
		}))
	}
	return principal
}

// apiHandler is a handler that has already been given its authenticated caller.
type apiHandler func(http.ResponseWriter, *http.Request, pathValues, *Principal)

// requireScope wraps a handler so it only runs for a caller holding the scope.
func (s *Server) requireScope(scope string, next apiHandler) func(http.ResponseWriter, *http.Request, pathValues) {
	return func(w http.ResponseWriter, r *http.Request, values pathValues) {
		principal := s.authenticate(r)
		if principal == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="crypt"`)
			writeAPIError(w, http.StatusUnauthorized, "unauthenticated",
				"Present a bearer token or sign in.", nil)
			return
		}
		if !principal.Has(scope) {
			writeAPIError(w, http.StatusForbidden, "insufficient_scope",
				"This endpoint requires the "+scope+" scope.",
				map[string]any{"required_scope": scope})
			return
		}
		if !s.apiCSRFOK(w, r, principal) {
			return
		}
		next(w, r, values, principal)
	}
}

// requireAuthenticated wraps a handler that any authenticated caller may use.
func (s *Server) requireAuthenticated(next apiHandler) func(http.ResponseWriter, *http.Request, pathValues) {
	return func(w http.ResponseWriter, r *http.Request, values pathValues) {
		principal := s.authenticate(r)
		if principal == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="crypt"`)
			writeAPIError(w, http.StatusUnauthorized, "unauthenticated",
				"Present a bearer token or sign in.", nil)
			return
		}
		if !s.apiCSRFOK(w, r, principal) {
			return
		}
		next(w, r, values, principal)
	}
}

// apiCSRFOK enforces CSRF protection for callers authenticated by session
// cookie. A bearer token is not sent automatically by a browser, so token
// callers are exempt.
func (s *Server) apiCSRFOK(w http.ResponseWriter, r *http.Request, principal *Principal) bool {
	if !principal.ViaSession || !isUnsafeMethod(r.Method) {
		return true
	}
	if s.csrfManager == nil || s.csrfManager.ValidateHeader(r) {
		return true
	}
	writeAPIError(w, http.StatusForbidden, "csrf_token_invalid",
		"A session-authenticated write must send the CSRF token in the "+CSRFHeaderName+" header.", nil)
	return false
}
