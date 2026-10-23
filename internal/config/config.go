// Package config loads bot-api-server settings from the environment.
package config

import (
	"fmt"
	"strings"
)

// Config is the process configuration. Secrets come from the environment
// and are never logged.
type Config struct {
	Listen                string
	DatabaseURL           string
	MigrateDatabaseURL    string
	GoogleClientID        string
	GoogleClientSecret    string
	GoogleIssuer          string
	OAuthRedirectURIs     []string
	DeviceVerificationURI string
	AgentWSURL            string
	PublicOrigin          string
	TrustedProxy          string
	MCPResource           string
	ConsoleOrigin         string
	MCPClientSecretFile   string
	// SecretsKeyFile is optional. Empty means env-set and registry writes
	// that need the key are unavailable. The file contents are not stored here.
	SecretsKeyFile string
	// RegistryAllowPrivate is BOT_API_REGISTRY_ALLOW_PRIVATE=1 (dev only). It
	// lifts only the address and port checks on registry tag and digest lookups.
	RegistryAllowPrivate bool
}

const defaultIssuer = "https://accounts.google.com"

// FromEnv reads configuration. migrateOnly skips the fields a normal
// server needs and requires only BOT_API_MIGRATE_DATABASE_URL.
func FromEnv(getenv func(string) string, migrateOnly bool) (Config, error) {
	cfg := Config{
		Listen:                strings.TrimSpace(getenv("BOT_API_LISTEN")),
		DatabaseURL:           strings.TrimSpace(getenv("DATABASE_URL")),
		MigrateDatabaseURL:    strings.TrimSpace(getenv("BOT_API_MIGRATE_DATABASE_URL")),
		GoogleClientID:        strings.TrimSpace(getenv("BOT_API_GOOGLE_CLIENT_ID")),
		GoogleClientSecret:    strings.TrimSpace(getenv("BOT_API_GOOGLE_CLIENT_SECRET")),
		GoogleIssuer:          strings.TrimSpace(getenv("BOT_API_GOOGLE_ISSUER")),
		DeviceVerificationURI: strings.TrimSpace(getenv("BOT_API_DEVICE_VERIFICATION_URI")),
		AgentWSURL:            strings.TrimSpace(getenv("BOT_API_AGENT_WS_URL")),
		PublicOrigin:          strings.TrimSpace(getenv("BOT_API_PUBLIC_ORIGIN")),
		TrustedProxy:          strings.TrimSpace(getenv("BOT_API_TRUSTED_PROXY")),
		MCPResource:           strings.TrimSpace(getenv("BOT_API_MCP_RESOURCE")),
		ConsoleOrigin:         strings.TrimSpace(getenv("BOT_API_CONSOLE_ORIGIN")),
		MCPClientSecretFile:   strings.TrimSpace(getenv("BOT_API_MCP_CLIENT_SECRET_FILE")),
		SecretsKeyFile:        strings.TrimSpace(getenv("BOT_SECRETS_KEY_FILE")),
		RegistryAllowPrivate:  strings.TrimSpace(getenv("BOT_API_REGISTRY_ALLOW_PRIVATE")) == "1",
	}
	if cfg.GoogleIssuer == "" {
		cfg.GoogleIssuer = defaultIssuer
	}
	for _, part := range strings.Split(getenv("BOT_API_OAUTH_REDIRECT_URIS"), ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			cfg.OAuthRedirectURIs = append(cfg.OAuthRedirectURIs, part)
		}
	}
	if migrateOnly {
		if cfg.MigrateDatabaseURL == "" {
			return Config{}, fmt.Errorf("BOT_API_MIGRATE_DATABASE_URL is required for --migrate")
		}
		return cfg, nil
	}
	var missing []string
	require := func(name, val string) {
		if val == "" {
			missing = append(missing, name)
		}
	}
	require("BOT_API_LISTEN", cfg.Listen)
	require("DATABASE_URL", cfg.DatabaseURL)
	require("BOT_API_GOOGLE_CLIENT_ID", cfg.GoogleClientID)
	require("BOT_API_GOOGLE_CLIENT_SECRET", cfg.GoogleClientSecret)
	require("BOT_API_DEVICE_VERIFICATION_URI", cfg.DeviceVerificationURI)
	require("BOT_API_AGENT_WS_URL", cfg.AgentWSURL)
	if len(cfg.OAuthRedirectURIs) == 0 {
		missing = append(missing, "BOT_API_OAUTH_REDIRECT_URIS")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing config: %s", strings.Join(missing, ", "))
	}
	if strings.ContainsAny(cfg.AgentWSURL, "' \t\r\n") {
		return Config{}, fmt.Errorf("BOT_API_AGENT_WS_URL must not contain quotes or whitespace")
	}
	return cfg, nil
}

// RedirectAllowed reports whether uri is on the OAuth allowlist.
func (c Config) RedirectAllowed(uri string) bool {
	for _, allowed := range c.OAuthRedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}
