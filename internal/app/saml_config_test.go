package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadSAMLConfigDefaults(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "saml.yaml")
	err := os.WriteFile(cfgPath, []byte(`root_url: https://crypt.example.com
idp_metadata_path: /tmp/metadata.xml
certificate_path: /tmp/sp.crt
private_key_path: /tmp/sp.key
`), 0o600)
	require.NoError(t, err)

	cfg, err := LoadSAMLConfig(cfgPath)
	require.NoError(t, err)
	require.Equal(t, "/saml2/metadata/", cfg.MetadataURLPath)
	require.Equal(t, "/saml2/acs/", cfg.AcsURLPath)
	require.Equal(t, "/saml2/ls/", cfg.SloURLPath)
	require.Equal(t, "memberOf", cfg.GroupsAttribute)
	require.Equal(t, "saml", cfg.DefaultAuthSource)
	require.Equal(t, "/", cfg.DefaultRedirectURI)
}

func TestLoadSAMLConfigRequiresFields(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "saml.yaml")
	err := os.WriteFile(cfgPath, []byte(`root_url: ""`), 0o600)
	require.NoError(t, err)

	_, err = LoadSAMLConfig(cfgPath)
	require.Error(t, err)
}
