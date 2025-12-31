package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"crypt-server/internal/crypto"
	"github.com/fernet/fernet-go"
	"github.com/stretchr/testify/require"
)

func TestConvertFixtureBadSecret(t *testing.T) {
	legacyKey := fernet.Key{}
	require.NoError(t, legacyKey.Generate())
	legacyDecoded := fernet.MustDecodeKeys(string(legacyKey.Encode()))

	codec, err := crypto.NewAesGcmCodecFromBase64Key(validKeyBase64())
	require.NoError(t, err)

	entries := []fixtureEntry{
		{Model: "server.secret", PK: 20, Fields: map[string]interface{}{"computer": 10, "secret_type": "recovery_key", "secret": "not-a-token"}},
	}

	_, err = convertFixture(entries, legacyDecoded[0], codec)
	require.Error(t, err)
}

func TestConvertFixtureMissingSecret(t *testing.T) {
	legacyKey := fernet.Key{}
	require.NoError(t, legacyKey.Generate())
	legacyDecoded := fernet.MustDecodeKeys(string(legacyKey.Encode()))

	codec, err := crypto.NewAesGcmCodecFromBase64Key(validKeyBase64())
	require.NoError(t, err)

	entries := []fixtureEntry{
		{Model: "server.secret", PK: 21, Fields: map[string]interface{}{"computer": 10, "secret_type": "recovery_key"}},
	}

	_, err = convertFixture(entries, legacyDecoded[0], codec)
	require.Error(t, err)
}

func TestRunImportFixtureMissingArgs(t *testing.T) {
	err := runImportFixture([]string{"--input", "", "--output", ""})
	require.Error(t, err)
}

func TestRunImportFixtureMissingKeys(t *testing.T) {
	tmp := t.TempDir()
	entries := []fixtureEntry{{Model: "server.computer", PK: 10, Fields: map[string]interface{}{"serial": "SERIAL"}}}
	payload, err := json.Marshal(entries)
	require.NoError(t, err)

	inputPath := filepath.Join(tmp, "fixture.json")
	outputPath := filepath.Join(tmp, "output.json")
	require.NoError(t, os.WriteFile(inputPath, payload, 0o600))

	err = runImportFixture([]string{"--input", inputPath, "--output", outputPath})
	require.Error(t, err)
}

func validKeyBase64() string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(key)
}
