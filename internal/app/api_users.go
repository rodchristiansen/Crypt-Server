package app

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"crypt-server/internal/store"
)

// minPasswordLength is the floor for a password set through the API. The web
// UI has no explicit policy; the API states one rather than inheriting none.
const minPasswordLength = 12

func (s *Server) resolveUser(w http.ResponseWriter, values pathValues) (*store.User, bool) {
	id, err := strconv.Atoi(values["id"])
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "user_not_found", "No user with that id.", nil)
		return nil, false
	}
	user, err := s.store.GetUserByID(id)
	if err != nil {
		if err == store.ErrNotFound {
			writeAPIError(w, http.StatusNotFound, "user_not_found", "No user with that id.", nil)
			return nil, false
		}
		s.logger.Printf("api: user lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return nil, false
	}
	return user, true
}

type meResponse struct {
	Username          string   `json:"username"`
	Kind              string   `json:"kind"`
	IsStaff           bool     `json:"is_staff"`
	CanApprove        bool     `json:"can_approve"`
	LocalLoginEnabled bool     `json:"local_login_enabled"`
	ViaSession        bool     `json:"via_session"`
	TokenName         string   `json:"token_name,omitempty"`
	Scopes            []string `json:"scopes"`
}

// handleAPIMe describes the calling principal. Every client needs this first,
// to know what it is allowed to do.
func (s *Server) handleAPIMe(w http.ResponseWriter, _ *http.Request, _ pathValues, principal *Principal) {
	writeAPIJSON(w, http.StatusOK, meResponse{
		Username:          principal.Username,
		Kind:              principal.Kind,
		IsStaff:           principal.IsStaff,
		CanApprove:        principal.CanApprove,
		LocalLoginEnabled: principal.LocalLoginEnabled,
		ViaSession:        principal.ViaSession,
		TokenName:         principal.TokenName,
		Scopes:            principal.Scopes,
	})
}

func (s *Server) handleAPIListUsers(w http.ResponseWriter, r *http.Request, _ pathValues, _ *Principal) {
	filter := store.UserFilter{
		Search:     strings.TrimSpace(r.URL.Query().Get("search")),
		AuthSource: strings.TrimSpace(r.URL.Query().Get("auth_source")),
		IsStaff:    queryBool(r, "is_staff"),
		CanApprove: queryBool(r, "can_approve"),
	}
	pageNumber, perPage, offset := paginationFrom(r)
	filter.Limit = perPage
	filter.Offset = offset

	count, err := s.store.CountUsersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: count users failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	users, err := s.store.ListUsersFiltered(filter)
	if err != nil {
		s.logger.Printf("api: list users failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	results := make([]userView, 0, len(users))
	for _, user := range users {
		results = append(results, newUserView(user))
	}
	writeAPIPage(w, count, pageNumber, perPage, results)
}

type createUserBody struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	IsStaff           bool   `json:"is_staff"`
	CanApprove        bool   `json:"can_approve"`
	LocalLoginEnabled bool   `json:"local_login_enabled"`
	MustResetPassword bool   `json:"must_reset_password"`
	AuthSource        string `json:"auth_source"`
}

func (s *Server) handleAPICreateUser(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	var body createUserBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	username := strings.TrimSpace(body.Username)
	if username == "" {
		writeAPIError(w, http.StatusBadRequest, "username_required", "A username is required.", nil)
		return
	}
	authSource := strings.TrimSpace(body.AuthSource)
	if authSource == "" {
		authSource = "local"
	}
	if _, err := s.store.GetUserByUsername(username); err == nil {
		writeAPIError(w, http.StatusConflict, "user_exists", "A user with that name already exists.", nil)
		return
	} else if err != store.ErrNotFound {
		s.logger.Printf("api: create user lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}

	passwordHash := ""
	if body.LocalLoginEnabled {
		if len(body.Password) < minPasswordLength {
			writeAPIError(w, http.StatusBadRequest, "password_too_short",
				"A local-login user needs a password of at least "+strconv.Itoa(minPasswordLength)+" characters.", nil)
			return
		}
		hashed, err := hashPassword(body.Password)
		if err != nil {
			s.logger.Printf("api: hash password failed: %v", err)
			writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
			return
		}
		passwordHash = hashed
	}

	user, err := s.store.AddUser(username, passwordHash, body.IsStaff, body.CanApprove,
		body.LocalLoginEnabled, body.MustResetPassword, authSource)
	if err != nil {
		s.logger.Printf("api: create user failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventUserCreated,
		TargetType: "user",
		TargetID:   strconv.Itoa(user.ID),
		TargetUser: user.Username,
		Metadata: map[string]any{
			"is_staff":            user.IsStaff,
			"can_approve":         user.CanApprove,
			"local_login_enabled": user.LocalLoginEnabled,
			"auth_source":         user.AuthSource,
		},
	})
	writeAPIJSON(w, http.StatusCreated, newUserView(user))
}

func (s *Server) handleAPIGetUser(w http.ResponseWriter, _ *http.Request, values pathValues, _ *Principal) {
	user, ok := s.resolveUser(w, values)
	if !ok {
		return
	}
	writeAPIJSON(w, http.StatusOK, newUserView(user))
}

type patchUserBody struct {
	Username          *string `json:"username"`
	IsStaff           *bool   `json:"is_staff"`
	CanApprove        *bool   `json:"can_approve"`
	LocalLoginEnabled *bool   `json:"local_login_enabled"`
	MustResetPassword *bool   `json:"must_reset_password"`
	AuthSource        *string `json:"auth_source"`
}

func (s *Server) handleAPIPatchUser(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	user, ok := s.resolveUser(w, values)
	if !ok {
		return
	}
	var body patchUserBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	username := user.Username
	if body.Username != nil {
		username = strings.TrimSpace(*body.Username)
		if username == "" {
			writeAPIError(w, http.StatusBadRequest, "username_required", "A username is required.", nil)
			return
		}
	}
	isStaff := user.IsStaff
	if body.IsStaff != nil {
		isStaff = *body.IsStaff
	}
	canApprove := user.CanApprove
	if body.CanApprove != nil {
		canApprove = *body.CanApprove
	}
	localLogin := user.LocalLoginEnabled
	if body.LocalLoginEnabled != nil {
		localLogin = *body.LocalLoginEnabled
	}
	mustReset := user.MustResetPassword
	if body.MustResetPassword != nil {
		mustReset = *body.MustResetPassword
	}
	authSource := user.AuthSource
	if body.AuthSource != nil && strings.TrimSpace(*body.AuthSource) != "" {
		authSource = strings.TrimSpace(*body.AuthSource)
	}

	updated, err := s.store.UpdateUser(user.ID, username, isStaff, canApprove, localLogin, mustReset, authSource)
	if err != nil {
		s.logger.Printf("api: update user failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventUserUpdated,
		TargetType: "user",
		TargetID:   strconv.Itoa(updated.ID),
		TargetUser: updated.Username,
		Metadata: map[string]any{
			"is_staff":            updated.IsStaff,
			"can_approve":         updated.CanApprove,
			"local_login_enabled": updated.LocalLoginEnabled,
			"must_reset_password": updated.MustResetPassword,
			"auth_source":         updated.AuthSource,
		},
	})
	writeAPIJSON(w, http.StatusOK, newUserView(updated))
}

func (s *Server) handleAPIDeleteUser(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	user, ok := s.resolveUser(w, values)
	if !ok {
		return
	}
	if user.Username == principal.Username {
		writeAPIError(w, http.StatusConflict, "cannot_delete_self", "You cannot delete your own account.", nil)
		return
	}
	if err := s.store.DeleteUser(user.ID); err != nil {
		s.logger.Printf("api: delete user failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventUserDeleted,
		TargetType: "user",
		TargetID:   strconv.Itoa(user.ID),
		TargetUser: user.Username,
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}

type adminPasswordBody struct {
	Password          string `json:"password"`
	MustResetPassword bool   `json:"must_reset_password"`
	Reason            string `json:"reason"`
}

func (s *Server) handleAPIAdminSetPassword(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	user, ok := s.resolveUser(w, values)
	if !ok {
		return
	}
	var body adminPasswordBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if len(body.Password) < minPasswordLength {
		writeAPIError(w, http.StatusBadRequest, "password_too_short",
			"The password must be at least "+strconv.Itoa(minPasswordLength)+" characters.", nil)
		return
	}
	hashed, err := hashPassword(body.Password)
	if err != nil {
		s.logger.Printf("api: hash password failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	updated, err := s.store.UpdateUserPassword(user.ID, hashed, body.MustResetPassword)
	if err != nil {
		s.logger.Printf("api: set password failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventUserPasswordReset,
		TargetType: "user",
		TargetID:   strconv.Itoa(updated.ID),
		TargetUser: updated.Username,
		Reason:     strings.TrimSpace(body.Reason),
		Metadata:   map[string]any{"must_reset_password": updated.MustResetPassword},
	})
	writeAPIJSON(w, http.StatusOK, newUserView(updated))
}

type selfPasswordBody struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleAPIChangeOwnPassword(w http.ResponseWriter, r *http.Request, _ pathValues, principal *Principal) {
	if principal.Username == "" {
		writeAPIError(w, http.StatusForbidden, "user_required", "Only a user can change a password.", nil)
		return
	}
	var body selfPasswordBody
	if !decodeJSONBody(w, r, &body) {
		return
	}
	user, err := s.store.GetUserByUsername(principal.Username)
	if err != nil {
		s.logger.Printf("api: change password lookup failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	if !user.LocalLoginEnabled {
		writeAPIError(w, http.StatusConflict, "local_login_disabled",
			"This account signs in through the identity provider and has no local password.", nil)
		return
	}
	if user.PasswordHash == "" || !verifyPassword(body.CurrentPassword, user.PasswordHash) {
		writeAPIError(w, http.StatusForbidden, "current_password_incorrect", "The current password is incorrect.", nil)
		return
	}
	if len(body.NewPassword) < minPasswordLength {
		writeAPIError(w, http.StatusBadRequest, "password_too_short",
			"The password must be at least "+strconv.Itoa(minPasswordLength)+" characters.", nil)
		return
	}
	hashed, err := hashPassword(body.NewPassword)
	if err != nil {
		s.logger.Printf("api: hash password failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	if _, err := s.store.UpdateUserPassword(user.ID, hashed, false); err != nil {
		s.logger.Printf("api: change password failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventUserPasswordReset,
		TargetType: "user",
		TargetID:   strconv.Itoa(user.ID),
		TargetUser: user.Username,
		Metadata:   map[string]any{"self_service": true},
	})
	writeAPIJSON(w, http.StatusNoContent, nil)
}

func (s *Server) handleAPIRevokeUserSessions(w http.ResponseWriter, r *http.Request, values pathValues, principal *Principal) {
	user, ok := s.resolveUser(w, values)
	if !ok {
		return
	}
	revokedAt := time.Now()
	if err := s.store.RevokeUserSessions(user.ID, revokedAt); err != nil {
		s.logger.Printf("api: revoke sessions failed: %v", err)
		writeAPIError(w, http.StatusInternalServerError, "internal_error", "Something went wrong.", nil)
		return
	}
	s.recordEvent(r, principal, eventRecord{
		Action:     EventUserSessionsRevoked,
		TargetType: "user",
		TargetID:   strconv.Itoa(user.ID),
		TargetUser: user.Username,
	})
	writeAPIJSON(w, http.StatusOK, map[string]any{
		"username":   user.Username,
		"revoked_at": revokedAt.UTC().Format(time.RFC3339),
	})
}
