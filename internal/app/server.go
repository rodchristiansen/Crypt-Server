package app

import (
	"crypt-server/internal/store"
	"log"
	"net/http"
	"strings"
)

type Server struct {
	store    *store.Store
	renderer *Renderer
	logger   *log.Logger
}

func NewServer(store *store.Store, renderer *Renderer, logger *log.Logger) *Server {
	return &Server{store: store, renderer: renderer, logger: logger}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/ajax/", s.handleTableAjax)
	mux.HandleFunc("/new/computer/", s.handleNewComputer)
	mux.HandleFunc("/new/secret/", s.handleNewSecret)
	mux.HandleFunc("/info/secret/", s.handleSecretInfo)
	mux.HandleFunc("/info/", s.handleComputerInfo)
	mux.HandleFunc("/request/", s.handleRequest)
	mux.HandleFunc("/retrieve/", s.handleRetrieve)
	mux.HandleFunc("/approve/", s.handleApprove)
	mux.HandleFunc("/manage-requests/", s.handleManageRequests)
	mux.HandleFunc("/login/", s.handleLogin)
	mux.HandleFunc("/logout/", s.handleLogout)
	mux.HandleFunc("/checkin/", s.handleCheckin)
	mux.HandleFunc("/verify/", s.handleVerify)

	return withTrailingSlashRedirect(mux)
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
