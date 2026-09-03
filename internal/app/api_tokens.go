package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypt-server/internal/store"
)

type createTokenBody struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Scopes    []string `json:"scopes"`
	Username  string   `json:"username"`
	ExpiresAt string   `json:"expires_at"`
}

type createTokenResponse struct {
	Token tokenView `json:"token"`
	// Secret is the plaintext credential. It is shown exactly once, here.
	Secret string `json:"secret"`
}

func (s *Server) handleAPIListTokens(w http.ResponseWriter, _ *http.Request, _ pathValues, _ *Principal) {
	tokens, err := s.store.ListAPITokens()
	if err != nil {
		s.logger.Printf("api: list tokens failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]tokenView, 0, len(tokens))
	for _, token := range tokens {
		results = append(results, newTokenView(token))
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) handleAPICreateToken(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body createTokenBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeAPIError(w, http.StatusBadRequest, "name_required", "A name is required so the token can be recognised later.", nil)
		return
	}
	kind := strings.TrimSpace(body.Kind)
	if kind == "" {
		kind = store.TokenKindService
	}
	if _, ok := tokenKindPrefixes[kind]; !ok {
		writeAPIError(w, http.StatusBadRequest, "invalid_kind",
			"Kind must be device, service or user.", nil)
		return
	}
	scopes, err := normaliseScopes(kind, body.Scopes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_scopes", err.Error(), nil)
		return
	}

	username := strings.TrimSpace(body.Username)
	if kind == store.TokenKindUser {
		if username == "" {
			username = principal.Username
		}
		if username == "" {
			writeAPIError(w, http.StatusBadRequest, "username_required",
				"A user token needs a username to act as.", nil)
			return
		}
		if _, err := s.store.GetUserByUsername(username); err != nil {
			writeAPIError(w, http.StatusBadRequest, "user_not_found", "No such user.", nil)
			return
		}
	} else if username != "" {
		writeAPIError(w, http.StatusBadRequest, "username_not_allowed",
			"Only a user token may name a username.", nil)
		return
	}

	var expiresAt *time.Time
	if raw := strings.TrimSpace(body.ExpiresAt); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_expires_at",
				"expires_at must be an RFC 3339 timestamp.", nil)
			return
		}
		if !parsed.After(time.Now()) {
			writeAPIError(w, http.StatusBadRequest, "invalid_expires_at",
				"expires_at must be in the future.", nil)
			return
		}
		expiresAt = &parsed
	}

	plaintext, prefix, hash, err := generateToken(kind)
	if err != nil {
		s.logger.Printf("api: generate token failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	created, err := s.store.AddAPIToken(store.APIToken{
		Name:      name,
		Prefix:    prefix,
		TokenHash: hash,
		Kind:      kind,
		Scopes:    scopes,
		Username:  username,
		CreatedBy: principal.Actor(),
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		s.logger.Printf("api: create token failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventTokenCreated,
		TargetType: "token",
		TargetID:   strconv.Itoa(created.ID),
		TargetUser: created.Username,
		Metadata: map[string]any{
			"name":   created.Name,
			"kind":   created.Kind,
			"scopes": created.Scopes,
			"prefix": created.Prefix,
		},
	})
	writeAPIJSON(w, http.StatusCreated, createTokenResponse{
		Token:  newTokenView(created),
		Secret: plaintext,
	})
}

func (s *Server) handleAPIGetToken(w http.ResponseWriter, _ *http.Request, values pathValues, _ *Principal) {
	token, ok := s.resolveToken(w, values)
	if !ok {
		return
	}
	writeAPIJSON(w, http.StatusOK, newTokenView(token))
}

func (s *Server) resolveToken(w http.ResponseWriter, values pathValues) (*store.APIToken, bool) {
	id, err := strconv.Atoi(values["id"])
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "token_not_found", "No token with that id.", nil)
		return nil, false
	}
	token, err := s.store.GetAPITokenByID(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "token_not_found", "No token with that id.", nil)
			return nil, false
		}
		s.logger.Printf("api: token lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return nil, false
	}
	return token, true
}

func (s *Server) handleAPIRevokeToken(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	token, ok := s.resolveToken(w, values)
	if !ok {
		return
	}
	if err := s.store.RevokeAPIToken(token.ID, time.Now()); err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusConflict, "token_already_revoked", "That token is already revoked.", nil)
			return
		}
		s.logger.Printf("api: revoke token failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventTokenRevoked,
		TargetType: "token",
		TargetID:   strconv.Itoa(token.ID),
		TargetUser: token.Username,
		Metadata:   map[string]any{"name": token.Name, "prefix": token.Prefix},
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}

// handleAPIRotateToken issues a replacement carrying the same name, kind and
// scopes, then revokes the original.
func (s *Server) handleAPIRotateToken(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	token, ok := s.resolveToken(w, values)
	if !ok {
		return
	}
	plaintext, prefix, hash, err := generateToken(token.Kind)
	if err != nil {
		s.logger.Printf("api: rotate token generate failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	created, err := s.store.AddAPIToken(store.APIToken{
		Name:      token.Name,
		Prefix:    prefix,
		TokenHash: hash,
		Kind:      token.Kind,
		Scopes:    token.Scopes,
		Username:  token.Username,
		CreatedBy: principal.Actor(),
		CreatedAt: time.Now(),
		ExpiresAt: token.ExpiresAt,
	})
	if err != nil {
		s.logger.Printf("api: rotate token create failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	if err := s.store.RevokeAPIToken(token.ID, time.Now()); err != nil && err != store.ErrNotFound {
		s.logger.Printf("api: rotate token revoke failed: %v", err)
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventTokenCreated,
		TargetType: "token",
		TargetID:   strconv.Itoa(created.ID),
		TargetUser: created.Username,
		Metadata: map[string]any{
			"name":     created.Name,
			"rotated":  true,
			"replaces": token.Prefix,
		},
	})
	writeAPIJSON(w, http.StatusCreated, createTokenResponse{
		Token:  newTokenView(created),
		Secret: plaintext,
	})
}
