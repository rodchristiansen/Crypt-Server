package app

import (
	"crypt-server/internal/store"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"unicode"
)

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := TemplateData{
		Title:            "Crypt",
		User:             s.currentUser(r),
		Version:          "0.0.0-dev",
		Computers:        s.store.ListComputers(),
		OutstandingCount: len(s.store.ListOutstandingRequests()),
	}

	if err := s.renderer.Render(w, "index", data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleTableAjax(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	draw := 0
	if raw := r.URL.Query().Get("args"); raw != "" {
		var payload map[string]any
		if err := json.Unmarshal([]byte(raw), &payload); err == nil {
			if value, ok := payload["draw"].(float64); ok {
				draw = int(value)
			}
		}
	}

	computers := s.store.ListComputers()
	data["draw"] = draw
	data["recordsTotal"] = len(computers)
	data["recordsFiltered"] = len(computers)

	rows := make([][]string, 0, len(computers))
	for _, computer := range computers {
		serial := html.EscapeString(computer.Serial)
		computerName := html.EscapeString(computer.ComputerName)
		username := html.EscapeString(computer.Username)
		lastCheckin := ""
		if !computer.LastCheckin.IsZero() {
			lastCheckin = computer.LastCheckin.Format("2006-01-02 15:04")
		}

		link := fmt.Sprintf("/info/%d/", computer.ID)
		rows = append(rows, []string{
			fmt.Sprintf("<a href=\"%s\">%s</a>", link, serial),
			fmt.Sprintf("<a href=\"%s\">%s</a>", link, computerName),
			username,
			lastCheckin,
			fmt.Sprintf("<a class=\"btn btn-info btn-xs\" href=\"%s\">Info</a>", link),
		})
	}

	data["data"] = rows

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleNewComputer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := TemplateData{Title: "New Computer", User: s.currentUser(r)}
		if err := s.renderer.Render(w, "new_computer", data); err != nil {
			s.renderError(w, err)
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderError(w, err)
			return
		}
		serial := strings.TrimSpace(r.FormValue("serial"))
		username := strings.TrimSpace(r.FormValue("username"))
		computerName := strings.TrimSpace(r.FormValue("computername"))
		if serial == "" || computerName == "" {
			data := TemplateData{
				Title:        "New Computer",
				User:         s.currentUser(r),
				ErrorMessage: "Serial number and computer name are required.",
			}
			if err := s.renderer.Render(w, "new_computer", data); err != nil {
				s.renderError(w, err)
			}
			return
		}
		computer := s.store.AddComputer(serial, username, computerName)
		http.Redirect(w, r, fmt.Sprintf("/info/%d/", computer.ID), http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNewSecret(w http.ResponseWriter, r *http.Request) {
	computerID, err := idFromPath("/new/secret/", r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	computer, err := s.store.GetComputerByID(computerID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data := TemplateData{Title: "New Secret", User: s.currentUser(r), Computer: computer}
		if err := s.renderer.Render(w, "new_secret", data); err != nil {
			s.renderError(w, err)
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderError(w, err)
			return
		}
		secretType := strings.TrimSpace(r.FormValue("secret_type"))
		secret := strings.TrimSpace(r.FormValue("secret"))
		rotationRequired := r.FormValue("rotation_required") == "on"

		if secretType == "" || secret == "" {
			data := TemplateData{
				Title:        "New Secret",
				User:         s.currentUser(r),
				Computer:     computer,
				ErrorMessage: "Secret type and value are required.",
			}
			if err := s.renderer.Render(w, "new_secret", data); err != nil {
				s.renderError(w, err)
			}
			return
		}

		if _, err := s.store.AddSecret(computer.ID, secretType, secret, rotationRequired); err != nil {
			s.renderError(w, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/info/%d/", computer.ID), http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleComputerInfo(w http.ResponseWriter, r *http.Request) {
	identifier := strings.TrimPrefix(r.URL.Path, "/info/")
	identifier = strings.TrimSuffix(identifier, "/")
	if identifier == "" {
		http.NotFound(w, r)
		return
	}

	computer, err := s.lookupComputer(identifier)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	secrets, err := s.store.ListSecretsByComputer(computer.ID)
	if err != nil {
		s.renderError(w, err)
		return
	}

	data := TemplateData{
		Title:    "Computer Info",
		User:     s.currentUser(r),
		Computer: computer,
		Secrets:  secrets,
	}
	if err := s.renderer.Render(w, "computer_info", data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleSecretInfo(w http.ResponseWriter, r *http.Request) {
	secretID, err := idFromPath("/info/secret/", r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	secret, err := s.store.GetSecretByID(secretID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	computer, err := s.store.GetComputerByID(secret.ComputerID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	requests, _ := s.store.ListRequestsBySecret(secret.ID)
	canRequest := true
	for _, request := range requests {
		if request.RequestingUser == s.currentUser(r).Username && request.Approved == nil {
			canRequest = false
		}
	}
	approved := false
	approvedRequestID := 0
	for _, request := range requests {
		if request.RequestingUser == s.currentUser(r).Username && request.Approved != nil && *request.Approved {
			approved = true
			approvedRequestID = request.ID
		}
	}

	data := TemplateData{
		Title:             "Secret Info",
		User:              s.currentUser(r),
		Computer:          computer,
		Secret:            secret,
		CanRequest:        canRequest,
		RequestApproved:   approved,
		ApprovedRequestID: approvedRequestID,
		RequestsForSecret: requests,
	}
	if err := s.renderer.Render(w, "secret_info", data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	secretID, err := idFromPath("/request/", r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	secret, err := s.store.GetSecretByID(secretID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	computer, err := s.store.GetComputerByID(secret.ComputerID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data := TemplateData{Title: "Request Secret", User: s.currentUser(r), Secret: secret, Computer: computer}
		if err := s.renderer.Render(w, "request", data); err != nil {
			s.renderError(w, err)
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderError(w, err)
			return
		}
		reason := strings.TrimSpace(r.FormValue("reason_for_request"))
		user := s.currentUser(r)
		var approved *bool
		var approver string
		if user.CanApprove {
			approvedValue := true
			approved = &approvedValue
			approver = user.Username
		}
		_, err := s.store.AddRequest(secret.ID, user.Username, reason, approver, approved)
		if err != nil {
			s.renderError(w, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/info/secret/%d/", secret.ID), http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	requestID, err := idFromPath("/approve/", r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	req, err := s.store.GetRequestByID(requestID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	secret, err := s.store.GetSecretByID(req.SecretID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	computer, err := s.store.GetComputerByID(secret.ComputerID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		data := TemplateData{Title: "Approve Request", User: s.currentUser(r), Request: req, Secret: secret, Computer: computer}
		if err := s.renderer.Render(w, "approve", data); err != nil {
			s.renderError(w, err)
		}
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			s.renderError(w, err)
			return
		}
		approvedValue := r.FormValue("approved") == "1"
		reason := strings.TrimSpace(r.FormValue("reason_for_approval"))
		if _, err := s.store.ApproveRequest(req.ID, approvedValue, reason, s.currentUser(r).Username); err != nil {
			s.renderError(w, err)
			return
		}
		http.Redirect(w, r, "/manage-requests/", http.StatusSeeOther)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	requestID, err := idFromPath("/retrieve/", r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	req, err := s.store.GetRequestByID(requestID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	secret, err := s.store.GetSecretByID(req.SecretID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	computer, err := s.store.GetComputerByID(secret.ComputerID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	secretChars := make([]SecretChar, 0, len(secret.Secret))
	for _, char := range secret.Secret {
		entry := SecretChar{Char: string(char), Class: "other"}
		if unicode.IsLetter(char) {
			entry.Class = "letter"
		} else if unicode.IsDigit(char) {
			entry.Class = "number"
		}
		secretChars = append(secretChars, entry)
	}

	data := TemplateData{
		Title:       "Retrieve Secret",
		User:        s.currentUser(r),
		Request:     req,
		Secret:      secret,
		Computer:    computer,
		SecretChars: secretChars,
	}
	if err := s.renderer.Render(w, "retrieve", data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleManageRequests(w http.ResponseWriter, r *http.Request) {
	requests := s.store.ListOutstandingRequests()
	views := make([]RequestView, 0, len(requests))
	for _, req := range requests {
		secret, err := s.store.GetSecretByID(req.SecretID)
		if err != nil {
			continue
		}
		computer, err := s.store.GetComputerByID(secret.ComputerID)
		if err != nil {
			continue
		}
		views = append(views, RequestView{
			ID:               req.ID,
			Serial:           computer.Serial,
			ComputerName:     computer.ComputerName,
			RequestingUser:   req.RequestingUser,
			ReasonForRequest: req.ReasonForRequest,
			DateRequested:    req.DateRequested.Format("2006-01-02 15:04"),
		})
	}
	data := TemplateData{Title: "Manage Requests", User: s.currentUser(r), ManageRequests: views}
	if err := s.renderer.Render(w, "manage_requests", data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{Title: "Login", User: s.currentUser(r)}
	if err := s.renderer.Render(w, "login", data); err != nil {
		s.renderError(w, err)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login/", http.StatusSeeOther)
}

func (s *Server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("checkin endpoint pending"))
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("verify endpoint pending"))
}

func (s *Server) currentUser(r *http.Request) User {
	return User{
		Username:          "admin",
		IsAuthenticated:   true,
		IsStaff:           true,
		HasUsablePassword: true,
		CanApprove:        true,
	}
}

func (s *Server) renderError(w http.ResponseWriter, err error) {
	s.logger.Printf("handler error: %v", err)
	http.Error(w, "Something went wrong", http.StatusInternalServerError)
}

func idFromPath(prefix, path string) (int, error) {
	if !strings.HasPrefix(path, prefix) {
		return 0, errors.New("invalid path")
	}
	trimmed := strings.TrimPrefix(path, prefix)
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" {
		return 0, errors.New("missing id")
	}
	return strconv.Atoi(trimmed)
}

func (s *Server) lookupComputer(identifier string) (*store.Computer, error) {
	if id, err := strconv.Atoi(identifier); err == nil {
		return s.store.GetComputerByID(id)
	}
	return s.store.GetComputerBySerial(identifier)
}
