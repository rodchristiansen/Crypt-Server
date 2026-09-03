package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type SessionManager struct {
	key        []byte
	cookieName string
	ttl        time.Duration
}

func NewSessionManager(key []byte, cookieName string, ttl time.Duration) (*SessionManager, error) {
	if len(key) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	if cookieName == "" {
		return nil, errors.New("session cookie name is required")
	}
	if ttl <= 0 {
		return nil, errors.New("session ttl must be positive")
	}
	return &SessionManager{key: key, cookieName: cookieName, ttl: ttl}, nil
}

func (s *SessionManager) Create(username string) (string, error) {
	return s.createAt(username, time.Now())
}

func (s *SessionManager) createAt(username string, now time.Time) (string, error) {
	if username == "" {
		return "", errors.New("username is required")
	}
	payload := fmt.Sprintf("%s|%d", username, now.Unix())
	signature := s.sign(payload)
	raw := payload + "|" + signature
	return base64.RawURLEncoding.EncodeToString([]byte(raw)), nil
}

func (s *SessionManager) Validate(token string) (string, bool) {
	username, _, ok := s.validateWithIssuedAt(token, time.Now())
	return username, ok
}

// ValidateWithIssuedAt validates a session and also reports when it was
// issued, so a session created before an account's sessions were revoked can
// be rejected.
func (s *SessionManager) ValidateWithIssuedAt(token string) (string, time.Time, bool) {
	return s.validateWithIssuedAt(token, time.Now())
}

func (s *SessionManager) validateAt(token string, now time.Time) (string, bool) {
	username, _, ok := s.validateWithIssuedAt(token, now)
	return username, ok
}

func (s *SessionManager) validateWithIssuedAt(token string, now time.Time) (string, time.Time, bool) {
	if token == "" {
		return "", time.Time{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", time.Time{}, false
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 3 {
		return "", time.Time{}, false
	}
	username := parts[0]
	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	payload := parts[0] + "|" + parts[1]
	expected := s.sign(payload)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return "", time.Time{}, false
	}
	issuedAt := time.Unix(timestamp, 0)
	if now.After(issuedAt.Add(s.ttl)) {
		return "", time.Time{}, false
	}
	return username, issuedAt, true
}

func (s *SessionManager) SetCookie(w http.ResponseWriter, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
	})
}

func (s *SessionManager) ClearCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Secure:   secure,
	})
}

func (s *SessionManager) CookieName() string {
	return s.cookieName
}

func (s *SessionManager) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
