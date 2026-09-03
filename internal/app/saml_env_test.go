package app

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSAMLEnabledFromEnv(t *testing.T) {
	require.False(t, SAMLEnabledFromEnv())

	t.Setenv("SAML_ENABLED", "true")
	require.True(t, SAMLEnabledFromEnv())

	t.Setenv("SAML_ENABLED", "nonsense")
	require.False(t, SAMLEnabledFromEnv())
}

func TestLoadSAMLConfigFromEnvMapsTheFullSurface(t *testing.T) {
	t.Setenv("HOST_NAME", "https://crypt.example.edu/")
	t.Setenv("SAML_SP_ENTITY_ID", "https://crypt.example.edu/saml/metadata")
	t.Setenv("SAML_METADATA_URL", "https://idp.example.edu/federationmetadata.xml")
	t.Setenv("SAML_GROUPS_ATTRIBUTE", "groups")
	t.Setenv("SAML_STAFF_GROUPS", "crypt-admins, crypt-operators")
	t.Setenv("SAML_CAN_APPROVE_GROUPS", "service-desk")
	t.Setenv("SAML_USE_NAME_ID_AS_USERNAME", "false")
	t.Setenv("SAML_DEFAULT_REDIRECT_URI", "/manage-requests/")

	cfg, err := LoadSAMLConfigFromEnv()

	require.NoError(t, err)
	// The trailing slash is stripped so URLs are not built with a double slash.
	require.Equal(t, "https://crypt.example.edu", cfg.RootURL)
	require.Equal(t, "https://idp.example.edu/federationmetadata.xml", cfg.IDPMetadataURL)
	require.Equal(t, "groups", cfg.GroupsAttribute)
	require.Equal(t, []string{"crypt-admins", "crypt-operators"}, cfg.StaffGroups)
	require.Equal(t, []string{"service-desk"}, cfg.CanApproveGroups)
	require.False(t, cfg.UseNameIDAsUsername)
	require.Equal(t, "/manage-requests/", cfg.DefaultRedirectURI)
}

func TestLoadSAMLConfigFromEnvAppliesTheSameDefaultsAsTheFile(t *testing.T) {
	t.Setenv("HOST_NAME", "https://crypt.example.edu")
	t.Setenv("SAML_METADATA_URL", "https://idp.example.edu/metadata.xml")

	cfg, err := LoadSAMLConfigFromEnv()

	require.NoError(t, err)
	require.Equal(t, "memberOf", cfg.GroupsAttribute)
	require.Equal(t, "saml", cfg.DefaultAuthSource)
	require.Equal(t, "/", cfg.DefaultRedirectURI)
	require.Equal(t, "/saml2/metadata/", cfg.MetadataURLPath)
	require.Equal(t, "/saml2/acs/", cfg.AcsURLPath)
	require.Equal(t, "/saml2/ls/", cfg.SloURLPath)
	require.True(t, cfg.CreateUnknownUser)
	require.True(t, cfg.AllowIDPInitiated)
}

func TestLoadSAMLConfigFromEnvRequiresHostName(t *testing.T) {
	t.Setenv("SAML_METADATA_URL", "https://idp.example.edu/metadata.xml")

	_, err := LoadSAMLConfigFromEnv()

	require.Error(t, err)
	require.Contains(t, err.Error(), "HOST_NAME")
}

func TestLoadSAMLConfigFromEnvRequiresIDPMetadata(t *testing.T) {
	t.Setenv("HOST_NAME", "https://crypt.example.edu")

	_, err := LoadSAMLConfigFromEnv()

	require.Error(t, err)
	require.Contains(t, err.Error(), "SAML_METADATA_URL")
}

func TestLoadSAMLConfigFromEnvRequiresKeypairWhenSigning(t *testing.T) {
	t.Setenv("HOST_NAME", "https://crypt.example.edu")
	t.Setenv("SAML_METADATA_URL", "https://idp.example.edu/metadata.xml")
	t.Setenv("SAML_SIGN_REQUEST", "true")

	_, err := LoadSAMLConfigFromEnv()

	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")
}
