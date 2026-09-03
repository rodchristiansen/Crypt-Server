package main

import (
	"fmt"
	"strings"

	"crypt-server/internal/app"
	"crypt-server/internal/crypto"
	"crypt-server/internal/store"
)

// createAPIToken mints the first API token from the command line, since there
// is no token to authenticate the API's own token endpoint with yet.
func createAPIToken(dataStore store.Store, name, kind, scopes, username string) (string, error) {
	requested := make([]string, 0)
	for _, scope := range strings.Split(scopes, ",") {
		trimmed := strings.TrimSpace(scope)
		if trimmed != "" {
			requested = append(requested, trimmed)
		}
	}
	if len(requested) == 0 {
		return "", fmt.Errorf("pass -token-scopes with at least one of: %s", strings.Join(store.AllScopes, ", "))
	}
	plaintext, _, err := app.MintToken(dataStore, name, kind, requested, username, "cli")
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

// rekeySecrets re-encrypts every stored secret under a new field encryption
// key. It is a command-line operation on purpose: a new encryption key should
// never travel over HTTP.
func rekeySecrets(dataStore store.Store, newKeyBase64 string) (int, error) {
	if strings.TrimSpace(newKeyBase64) == "" {
		return 0, fmt.Errorf("set NEW_FIELD_ENCRYPTION_KEY to the replacement key")
	}
	codec, err := crypto.NewAesGcmCodecFromBase64Key(newKeyBase64)
	if err != nil {
		return 0, fmt.Errorf("invalid new encryption key: %w", err)
	}
	return dataStore.RekeySecrets(codec)
}
