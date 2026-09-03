package app

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type SAMLConfig struct {
	RootURL             string            `yaml:"root_url"`
	EntityID            string            `yaml:"entity_id"`
	IDPMetadataPath     string            `yaml:"idp_metadata_path"`
	IDPMetadataURL      string            `yaml:"idp_metadata_url"`
	CertificatePath     string            `yaml:"certificate_path"`
	PrivateKeyPath      string            `yaml:"private_key_path"`
	AllowIDPInitiated   bool              `yaml:"allow_idp_initiated"`
	SignRequest         bool              `yaml:"sign_request"`
	UseNameIDAsUsername bool              `yaml:"use_name_id_as_username"`
	CreateUnknownUser   bool              `yaml:"create_unknown_user"`
	UsernameAttribute   string            `yaml:"username_attribute"`
	AttributeMapping    map[string]string `yaml:"attribute_mapping"`
	GroupsAttribute     string            `yaml:"groups_attribute"`
	StaffGroups         []string          `yaml:"staff_groups"`
	SuperuserGroups     []string          `yaml:"superuser_groups"`
	CanApproveGroups    []string          `yaml:"can_approve_groups"`
	DefaultAuthSource   string            `yaml:"auth_source"`
	DefaultLocalLogin   bool              `yaml:"local_login_enabled"`
	DefaultMustReset    bool              `yaml:"must_reset_password"`
	DefaultRedirectURI  string            `yaml:"default_redirect_uri"`
	MetadataURLPath     string            `yaml:"metadata_url_path"`
	AcsURLPath          string            `yaml:"acs_url_path"`
	SloURLPath          string            `yaml:"slo_url_path"`
}

func LoadSAMLConfig(path string) (*SAMLConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read saml config: %w", err)
	}
	var cfg SAMLConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse saml yaml: %w", err)
	}
	if err := finaliseSAMLConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// SAMLEnabledFromEnv reports whether SAML should be configured from the
// environment. It is the switch an environment-variable-only deployment uses
// in place of pointing at a config file.
func SAMLEnabledFromEnv() bool {
	return envSAMLBool("SAML_ENABLED", false)
}

// LoadSAMLConfigFromEnv builds a SAML configuration from environment
// variables. Container platforms generally hand configuration to a process as
// environment rather than as a mounted file, so this is an alternative to
// SAML_CONFIG_FILE rather than a replacement for it; the file wins when both
// are present.
func LoadSAMLConfigFromEnv() (*SAMLConfig, error) {
	cfg := SAMLConfig{
		RootURL:             strings.TrimRight(os.Getenv("HOST_NAME"), "/"),
		EntityID:            os.Getenv("SAML_SP_ENTITY_ID"),
		IDPMetadataPath:     os.Getenv("SAML_IDP_METADATA_PATH"),
		IDPMetadataURL:      os.Getenv("SAML_METADATA_URL"),
		CertificatePath:     os.Getenv("SAML_CERTIFICATE_PATH"),
		PrivateKeyPath:      os.Getenv("SAML_PRIVATE_KEY_PATH"),
		AllowIDPInitiated:   envSAMLBool("SAML_ALLOW_IDP_INITIATED", true),
		SignRequest:         envSAMLBool("SAML_SIGN_REQUEST", false),
		UseNameIDAsUsername: envSAMLBool("SAML_USE_NAME_ID_AS_USERNAME", true),
		CreateUnknownUser:   envSAMLBool("SAML_CREATE_UNKNOWN_USER", true),
		UsernameAttribute:   os.Getenv("SAML_USERNAME_ATTRIBUTE"),
		GroupsAttribute:     os.Getenv("SAML_GROUPS_ATTRIBUTE"),
		StaffGroups:         envSAMLList("SAML_STAFF_GROUPS"),
		SuperuserGroups:     envSAMLList("SAML_SUPERUSER_GROUPS"),
		CanApproveGroups:    envSAMLList("SAML_CAN_APPROVE_GROUPS"),
		DefaultAuthSource:   os.Getenv("SAML_AUTH_SOURCE"),
		DefaultLocalLogin:   envSAMLBool("SAML_LOCAL_LOGIN_ENABLED", false),
		DefaultMustReset:    envSAMLBool("SAML_MUST_RESET_PASSWORD", false),
		DefaultRedirectURI:  os.Getenv("SAML_DEFAULT_REDIRECT_URI"),
		MetadataURLPath:     os.Getenv("SAML_METADATA_URL_PATH"),
		AcsURLPath:          os.Getenv("SAML_ACS_URL_PATH"),
		SloURLPath:          os.Getenv("SAML_SLO_URL_PATH"),
	}
	if cfg.RootURL == "" {
		return nil, errors.New("SAML_ENABLED is set but HOST_NAME is missing")
	}
	if cfg.IDPMetadataPath == "" && cfg.IDPMetadataURL == "" {
		return nil, errors.New("SAML_ENABLED is set but neither SAML_METADATA_URL nor SAML_IDP_METADATA_PATH is set")
	}
	if err := finaliseSAMLConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// finaliseSAMLConfig validates a configuration and fills in the defaults,
// whichever source it came from.
func finaliseSAMLConfig(cfg *SAMLConfig) error {
	if cfg.RootURL == "" {
		return errors.New("saml config missing root_url")
	}
	if cfg.IDPMetadataPath == "" && cfg.IDPMetadataURL == "" {
		return errors.New("saml config missing idp metadata path or url")
	}
	// Certificate and private key are optional - only needed if sign_request is true
	// or if the IdP encrypts assertions
	if cfg.SignRequest && (cfg.CertificatePath == "" || cfg.PrivateKeyPath == "") {
		return errors.New("saml config requires certificate and private key when sign_request is enabled")
	}
	if cfg.GroupsAttribute == "" {
		cfg.GroupsAttribute = "memberOf"
	}
	if cfg.DefaultAuthSource == "" {
		cfg.DefaultAuthSource = "saml"
	}
	if cfg.DefaultRedirectURI == "" {
		cfg.DefaultRedirectURI = "/"
	}
	if cfg.MetadataURLPath == "" {
		cfg.MetadataURLPath = "/saml2/metadata/"
	}
	if cfg.AcsURLPath == "" {
		cfg.AcsURLPath = "/saml2/acs/"
	}
	if cfg.SloURLPath == "" {
		cfg.SloURLPath = "/saml2/ls/"
	}
	return nil
}

// envSAMLBool reads a boolean environment variable, falling back when unset or
// unparseable.
func envSAMLBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

// envSAMLList reads a comma-separated environment variable.
func envSAMLList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	values := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}
