package app

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// apiErrorBody is the single error shape every API endpoint returns.
type apiErrorBody struct {
	Error apiErrorDetail `json:"error"`
}

type apiErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func writeAPIError(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiErrorBody{Error: apiErrorDetail{
		Code:    code,
		Message: message,
		Details: details,
	}})
}

func writeAPIJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// page is the envelope every collection endpoint returns.
type page struct {
	Count   int `json:"count"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Results any `json:"results"`
}

func writeAPIPage(w http.ResponseWriter, count, pageNumber, perPage int, results any) {
	writeAPIJSON(w, http.StatusOK, page{
		Count:   count,
		Page:    pageNumber,
		PerPage: perPage,
		Results: results,
	})
}

// paginationFrom reads page and per_page from the query string, clamping
// per_page to maxPageSize.
func paginationFrom(r *http.Request) (pageNumber, perPage, offset int) {
	pageNumber = 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			pageNumber = parsed
		}
	}
	perPage = defaultPageSize
	if raw := r.URL.Query().Get("per_page"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			perPage = parsed
		}
	}
	if perPage > maxPageSize {
		perPage = maxPageSize
	}
	return pageNumber, perPage, (pageNumber - 1) * perPage
}

// decodeJSONBody reads a JSON request body into target, rejecting unknown
// fields so a typo in a client payload is an error rather than a silent no-op.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Body == nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_body", "A JSON body is required.", nil)
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_body", "The request body is not valid JSON: "+err.Error(), nil)
		return false
	}
	return true
}

// queryBool reads a tri-state boolean query parameter. A missing or
// unparseable value yields nil, meaning "no constraint".
func queryBool(r *http.Request, name string) *bool {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return nil
	}
	return &parsed
}

// queryInt reads an integer query parameter, returning fallback when absent.
func queryInt(r *http.Request, name string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

// queryTime reads an RFC 3339 timestamp query parameter.
func queryTime(r *http.Request, name string) *time.Time {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil
	}
	return &parsed
}

// formatTime renders a timestamp in the API's RFC 3339 UTC form. A zero time
// is rendered as null.
func formatTime(value time.Time) *string {
	if value.IsZero() {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339)
	return &formatted
}

func formatTimePointer(value *time.Time) *string {
	if value == nil {
		return nil
	}
	return formatTime(*value)
}

// writeCSV streams a CSV export with the given filename.
func writeCSV(w http.ResponseWriter, filename string, header []string, rows [][]string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
	writer := csv.NewWriter(w)
	_ = writer.Write(header)
	for _, row := range rows {
		_ = writer.Write(row)
	}
	writer.Flush()
}

// encodeJSON marshals a payload for delivery outside an HTTP response.
func encodeJSON(payload any) ([]byte, error) {
	return json.Marshal(payload)
}
