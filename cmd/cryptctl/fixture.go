package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"crypt-server/internal/crypto"
	"github.com/fernet/fernet-go"
)

func parseFixture(data []byte) ([]fixtureEntry, error) {
	var entries []fixtureEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func convertFixture(entries []fixtureEntry, legacyKey *fernet.Key, newCodec *crypto.AesGcmCodec) (*migrationOutput, error) {
	users := make(map[int]userOut)
	usernames := make(map[int]string)
	computers := make([]computerOut, 0)
	secrets := make([]secretOut, 0)
	requests := make([]requestOut, 0)

	for _, entry := range entries {
		switch entry.Model {
		case "auth.user":
			username := getString(entry.Fields, "username")
			user := userOut{
				ID:       entry.PK,
				Username: username,
				Email:    getString(entry.Fields, "email"),
				IsStaff:  getBool(entry.Fields, "is_staff"),
				IsSuper:  getBool(entry.Fields, "is_superuser"),
			}
			users[entry.PK] = user
			usernames[entry.PK] = username
		}
	}

	for _, entry := range entries {
		switch entry.Model {
		case "server.computer":
			computers = append(computers, computerOut{
				ID:           entry.PK,
				Serial:       getString(entry.Fields, "serial"),
				Username:     getString(entry.Fields, "username"),
				ComputerName: getString(entry.Fields, "computername"),
				LastCheckin:  getString(entry.Fields, "last_checkin"),
			})
		case "server.secret":
			ciphertext := getString(entry.Fields, "secret")
			plaintext, err := decryptLegacySecret(ciphertext, legacyKey)
			if err != nil {
				return nil, fmt.Errorf("decrypt secret %d: %w", entry.PK, err)
			}
			encrypted, err := newCodec.Encrypt(plaintext)
			if err != nil {
				return nil, fmt.Errorf("encrypt secret %d: %w", entry.PK, err)
			}
			secrets = append(secrets, secretOut{
				ID:               entry.PK,
				ComputerID:       getInt(entry.Fields, "computer"),
				SecretType:       getString(entry.Fields, "secret_type"),
				Secret:           encrypted,
				DateEscrowed:     getString(entry.Fields, "date_escrowed"),
				RotationRequired: getBool(entry.Fields, "rotation_required"),
			})
		case "server.request":
			requestingUser := usernameForID(usernames, getOptionalInt(entry.Fields, "requesting_user"))
			authUser := usernameForID(usernames, getOptionalInt(entry.Fields, "auth_user"))
			requests = append(requests, requestOut{
				ID:                entry.PK,
				SecretID:          getInt(entry.Fields, "secret"),
				RequestingUser:    requestingUser,
				Approved:          getOptionalBool(entry.Fields, "approved"),
				AuthUser:          authUser,
				ReasonForRequest:  getString(entry.Fields, "reason_for_request"),
				ReasonForApproval: getString(entry.Fields, "reason_for_approval"),
				DateRequested:     getString(entry.Fields, "date_requested"),
				DateApproved:      getString(entry.Fields, "date_approved"),
				Current:           getBool(entry.Fields, "current"),
			})
		}
	}

	userList := make([]userOut, 0, len(users))
	for _, user := range users {
		userList = append(userList, user)
	}

	return &migrationOutput{
		Computers: computers,
		Secrets:   secrets,
		Requests:  requests,
		Users:     userList,
	}, nil
}

func decryptLegacySecret(value string, key *fernet.Key) (string, error) {
	if value == "" {
		return "", errors.New("empty secret")
	}
	plaintext := fernet.VerifyAndDecrypt([]byte(value), 0*time.Second, []*fernet.Key{key})
	if plaintext == nil {
		return "", errors.New("invalid legacy token")
	}
	return string(plaintext), nil
}

func marshalOutput(output *migrationOutput) ([]byte, error) {
	return json.MarshalIndent(output, "", "  ")
}

func usernameForID(users map[int]string, id *int) string {
	if id == nil {
		return ""
	}
	if username, ok := users[*id]; ok {
		return username
	}
	return fmt.Sprintf("user-%d", *id)
}

func getString(fields map[string]interface{}, key string) string {
	value, ok := fields[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func getInt(fields map[string]interface{}, key string) int {
	value, ok := fields[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func getOptionalInt(fields map[string]interface{}, key string) *int {
	value, ok := fields[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case float64:
		value := int(typed)
		return &value
	case int:
		return &typed
	case json.Number:
		parsed, _ := typed.Int64()
		value := int(parsed)
		return &value
	default:
		return nil
	}
}

func getBool(fields map[string]interface{}, key string) bool {
	value, ok := fields[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		return false
	}
}

func getOptionalBool(fields map[string]interface{}, key string) *bool {
	value, ok := fields[key]
	if !ok {
		return nil
	}
	if value == nil {
		return nil
	}
	switch typed := value.(type) {
	case bool:
		return &typed
	default:
		return nil
	}
}
