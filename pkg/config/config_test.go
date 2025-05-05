package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReadConfigs(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "vaultconfigs*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testConfig := Configs{
		Environments: map[string]EnvironmentConfig{
			"dev": {
				URL:      "https://vault-dev.example.com",
				TokenEnv: "VAULT_DEV_TOKEN",
				Store:    "vault",
			},
			"prod": {
				URL:      "https://vault-prod.example.com",
				TokenEnv: "VAULT_PROD_TOKEN",
				Store:    "vault",
			},
		},
		RedactedKeys: []string{"password", "token"},
	}

	jsonData, err := json.Marshal(testConfig)
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}
	if _, err := tmpFile.Write(jsonData); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	// Test cases
	tests := []struct {
		name          string
		configPath    string
		expectError   bool
		expectedEnvs  []string
		errorContains string
	}{
		{
			name:         "Valid config",
			configPath:   tmpFile.Name(),
			expectError:  false,
			expectedEnvs: []string{"dev", "prod"},
		},
		{
			name:          "Non-existent file",
			configPath:    "non-existent-file.json",
			expectError:   true,
			errorContains: "does not exist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configs, err := ReadConfigs(tc.configPath)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
					return
				}
				if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tc.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			for _, env := range tc.expectedEnvs {
				if _, exists := configs.Environments[env]; !exists {
					t.Errorf("Expected environment %q not found in config", env)
				}
			}
		})
	}
}

func TestGetEnvironmentConfig(t *testing.T) {
	configs := &Configs{
		Environments: map[string]EnvironmentConfig{
			"dev": {
				URL:      "https://dev.example.com",
				TokenEnv: "VAULT_DEV_TOKEN",
				Store:    "vault",
			},
			"empty-url": {
				URL:      "",
				TokenEnv: "VAULT_SOME_TOKEN",
				Store:    "vault",
			},
			"empty-token": {
				URL:      "https://example.com",
				TokenEnv: "",
				Store:    "vault",
			},
			"non-vault": {
				URL:      "https://example.com",
				TokenEnv: "VAULT_TOKEN",
				Store:    "unsupported",
			},
		},
	}

	tests := []struct {
		name          string
		env           string
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid environment",
			env:         "dev",
			expectError: false,
		},
		{
			name:          "Non-existent environment",
			env:           "not-found",
			expectError:   true,
			errorContains: "not found",
		},
		{
			name:          "Empty URL",
			env:           "empty-url",
			expectError:   true,
			errorContains: "URL not specified",
		},
		{
			name:          "Empty token",
			env:           "empty-token",
			expectError:   true,
			errorContains: "token_env not specified",
		},
		{
			name:          "Unsupported store",
			env:           "non-vault",
			expectError:   true,
			errorContains: "unsupported store",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config, err := configs.GetEnvironmentConfig(tc.env)

			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
					return
				}
				if tc.errorContains != "" && !contains(err.Error(), tc.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tc.errorContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			expectedConfig := configs.Environments[tc.env]
			if config.URL != expectedConfig.URL {
				t.Errorf("Expected URL %q, got %q", expectedConfig.URL, config.URL)
			}
			if config.TokenEnv != expectedConfig.TokenEnv {
				t.Errorf("Expected TokenEnv %q, got %q", expectedConfig.TokenEnv, config.TokenEnv)
			}
			if config.Store != expectedConfig.Store {
				t.Errorf("Expected Store %q, got %q", expectedConfig.Store, config.Store)
			}
		})
	}
}

func contains(s, substr string) bool {
	return s != "" && substr != "" && s != substr && len(s) >= len(substr) && s != substr && contains_helper(s, substr)
}

func contains_helper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
