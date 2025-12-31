package app

import (
	"context"
	"crypt-server/internal/store"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Server struct {
	store          store.Store
	renderer       *Renderer
	logger         *log.Logger
	sessionManager *SessionManager
	settings       Settings
}

func NewServer(store store.Store, renderer *Renderer, logger *log.Logger, sessionManager *SessionManager, settings Settings) *Server {
	return &Server{
		store:          store,
		renderer:       renderer,
		logger:         logger,
		sessionManager: sessionManager,
		settings:       settings,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/login/", s.handleLogin)
	mux.HandleFunc("/logout/", s.handleLogout)
	mux.HandleFunc("/checkin/", s.handleCheckin)
	mux.HandleFunc("/verify/", s.handleVerify)
	mux.HandleFunc("/", s.requireAuth(s.handleIndex))
	mux.HandleFunc("/ajax/", s.requireAuth(s.handleTableAjax))
	mux.HandleFunc("/new/computer/", s.requireAuth(s.handleNewComputer))
	mux.HandleFunc("/new/secret/", s.requireAuth(s.handleNewSecret))
	mux.HandleFunc("/info/secret/", s.requireAuth(s.handleSecretInfo))
	mux.HandleFunc("/info/", s.requireAuth(s.handleComputerInfo))
	mux.HandleFunc("/request/", s.requireAuth(s.handleRequest))
	mux.HandleFunc("/retrieve/", s.requireAuth(s.handleRetrieve))
	mux.HandleFunc("/approve/", s.requireAuth(s.handleApprove))
	mux.HandleFunc("/manage-requests/", s.requireAuth(s.handleManageRequests))
	mux.HandleFunc("/admin/users/", s.requireAuth(s.handleAdminUsers))

	return withTrailingSlashRedirect(s.withUser(mux))
}

func withTrailingSlashRedirect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := s.currentUser(r)
		if !user.IsAuthenticated {
			http.Redirect(w, r, "/login/?next="+urlQueryEscape(r.URL.Path), http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func urlQueryEscape(value string) string {
	return url.QueryEscape(value)
}

type contextKey string

const userContextKey contextKey = "user"

func (s *Server) withUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := s.loadUserFromRequest(r)
		if user != nil {
			ctx := contextWithUser(r.Context(), user)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func contextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
