package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// EnvironmentConfig represents a Vault environment configuration
type EnvironmentConfig struct {
	URL      string `json:"url"`
	TokenEnv string `json:"token_env"`
	Store    string `json:"store"`
	Role     string `json:"role,omitempty"`
}

// Configs represents the entire configuration file
type Configs struct {
	Environments     map[string]EnvironmentConfig `json:"environments"`
	RedactedKeys     []string                     `json:"redacted_keys,omitempty"`
	RedactSecrets    *bool                        `json:"redact_secrets,omitempty"`
	RedactJSONValues *bool                        `json:"redact_json_values,omitempty"`
}

// DefaultRedactedKeys is a list of key names that typically contain sensitive information
var DefaultRedactedKeys = []string{
	"password", "secret", "token", "key", "credential", "auth", "pwd", "pass",
	"apikey", "api_key", "access_key", "secret_key", "private_key", "cert", "certificate",
}

// ShouldRedactSecrets returns whether secrets should be redacted
func (c *Configs) ShouldRedactSecrets() bool {
	if c.RedactSecrets == nil {
		return true // Default to true
	}
	return *c.RedactSecrets
}

// ShouldRedactJSONValues returns whether JSON values should be redacted
func (c *Configs) ShouldRedactJSONValues() bool {
	if c.RedactJSONValues == nil {
		return false // Default to false
	}
	return *c.RedactJSONValues
}

// GetRedactedKeys returns the list of keys that should be redacted
func (c *Configs) GetRedactedKeys() []string {
	if len(c.RedactedKeys) == 0 {
		return DefaultRedactedKeys
	}
	return c.RedactedKeys
}

// ReadConfigs reads the configuration file from the given path
func ReadConfigs(configPath string) (*Configs, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file %s does not exist", configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var configs Configs
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if configs.Environments == nil || len(configs.Environments) == 0 {
		return nil, fmt.Errorf("no environments defined in config file")
	}

	return &configs, nil
}

// GetEnvironmentConfig returns the configuration for the given environment
func (c *Configs) GetEnvironmentConfig(env string) (*EnvironmentConfig, error) {
	config, exists := c.Environments[env]
	if !exists {
		return nil, fmt.Errorf("environment %s not found in config", env)
	}

	if config.URL == "" && config.Store == "vault" {
		return nil, fmt.Errorf("URL not specified for vault environment %s", env)
	}

	if config.TokenEnv == "" && config.Store == "vault" {
		return nil, fmt.Errorf("token_env not specified for vault environment %s", env)
	}

	// For now, we only support vault store
	if config.Store != "" && config.Store != "vault" {
		return nil, fmt.Errorf("unsupported store type: %s", config.Store)
	}

	return &config, nil
}

// GetVaultToken retrieves the Vault token from the environment variable
func (e *EnvironmentConfig) GetVaultToken() (string, error) {
	if e.TokenEnv == "" {
		return "", fmt.Errorf("token_env not specified in the environment config")
	}

	token := os.Getenv(e.TokenEnv)
	if token == "" {
		return "", fmt.Errorf("environment variable %s not set or empty", e.TokenEnv)
	}

	return strings.TrimSpace(token), nil
}
