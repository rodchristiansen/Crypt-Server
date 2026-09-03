package app

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"crypt-server/internal/store"
)

const (
	tokenPrefixLength = 12
	tokenSecretBytes  = 32
)

// tokenKindPrefixes maps a token kind onto the human-readable marker that
// starts the token string, so a leaked credential is identifiable at a glance.
var tokenKindPrefixes = map[string]string{
	store.TokenKindDevice:  "ck_dev",
	store.TokenKindService: "ck_svc",
	store.TokenKindUser:    "ck_pat",
}

// generateToken mints a new API token. It returns the plaintext to hand to the
// caller once, along with the prefix and hash to persist.
func generateToken(kind string) (plaintext, prefix, hash string, err error) {
	marker, ok := tokenKindPrefixes[kind]
	if !ok {
		return "", "", "", fmt.Errorf("unknown token kind: %s", kind)
	}
	prefixBytes := make([]byte, tokenPrefixLength/2)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", "", "", fmt.Errorf("generate token prefix: %w", err)
	}
	secretBytes := make([]byte, tokenSecretBytes)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", "", fmt.Errorf("generate token secret: %w", err)
	}
	prefix = marker + "_" + hex.EncodeToString(prefixBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	plaintext = prefix + "." + secret
	return plaintext, prefix, hashToken(secret), nil
}

// hashToken hashes the secret half of a token. The secret carries 256 bits of
// entropy, so a plain SHA-256 is sufficient; a slow KDF would only add latency
// to every API request.
func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// splitToken separates a presented token into its prefix and secret halves.
func splitToken(presented string) (prefix, secret string, err error) {
	trimmed := strings.TrimSpace(presented)
	index := strings.LastIndex(trimmed, ".")
	if index <= 0 || index == len(trimmed)-1 {
		return "", "", errors.New("malformed token")
	}
	return trimmed[:index], trimmed[index+1:], nil
}

// verifyTokenSecret compares a presented secret against a stored hash in
// constant time.
func verifyTokenSecret(secret, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashToken(secret)), []byte(storedHash)) == 1
}

// normaliseScopes trims, de-duplicates and validates a requested scope list
// against the token kind.
func normaliseScopes(kind string, requested []string) ([]string, error) {
	seen := map[string]bool{}
	scopes := make([]string, 0, len(requested))
	for _, raw := range requested {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		if !store.IsKnownScope(scope) {
			return nil, fmt.Errorf("unknown scope: %s", scope)
		}
		if !store.ScopeAllowedForKind(kind, scope) {
			return nil, fmt.Errorf("scope %s cannot be granted to a %s token", scope, kind)
		}
		if seen[scope] {
			continue
		}
		seen[scope] = true
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	return scopes, nil
}

// MintToken creates an API token and returns its plaintext exactly once. It is
// exported so the crypt-server binary can bootstrap the first token before any
// token exists to authenticate with.
func MintToken(dataStore store.Store, name, kind string, scopes []string, username, createdBy string) (string, *store.APIToken, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("a token name is required")
	}
	kind = strings.TrimSpace(kind)
	if kind == "" {
		kind = store.TokenKindService
	}
	if _, ok := tokenKindPrefixes[kind]; !ok {
		return "", nil, fmt.Errorf("unknown token kind: %s", kind)
	}
	normalised, err := normaliseScopes(kind, scopes)
	if err != nil {
		return "", nil, err
	}
	username = strings.TrimSpace(username)
	if kind == store.TokenKindUser && username == "" {
		return "", nil, errors.New("a user token needs a username")
	}
	plaintext, prefix, hash, err := generateToken(kind)
	if err != nil {
		return "", nil, err
	}
	created, err := dataStore.AddAPIToken(store.APIToken{
		Name:      name,
		Prefix:    prefix,
		TokenHash: hash,
		Kind:      kind,
		Scopes:    normalised,
		Username:  username,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return "", nil, err
	}
	return plaintext, created, nil
}
