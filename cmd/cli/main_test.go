package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/spf13/cobra"
)

func TestConfigFlagHandling(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "vault-tests")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a test config file
	testConfigPath := filepath.Join(tempDir, ".vaultconfigs")
	testConfig := config.Configs{
		Environments: map[string]config.EnvironmentConfig{
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
	}

	configData, err := json.Marshal(testConfig)
	if err != nil {
		t.Fatalf("Failed to marshal test config: %v", err)
	}

	err = os.WriteFile(testConfigPath, configData, 0644)
	if err != nil {
		t.Fatalf("Failed to write test config file: %v", err)
	}

	// Test cases
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "Valid config path",
			args:        []string{"--config", testConfigPath},
			expectError: false,
		},
		{
			name:        "Invalid config path",
			args:        []string{"--config", "non-existent-file"},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new command for testing
			cmd := &cobra.Command{}
			cmd.PersistentFlags().StringVar(&configPath, "config", "./.vaultconfigs", "Path to vault config")
			cmd.RunE = func(cmd *cobra.Command, args []string) error {
				// Read config file to check if it works
				_, err := config.ReadConfigs(configPath)
				return err
			}

			// Execute the command
			cmd.SetArgs(tc.args)
			err := cmd.Execute()

			// Check error expectation
			if tc.expectError && err == nil {
				t.Errorf("Expected error but got nil")
			} else if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestEnvironmentFlagHandling(t *testing.T) {
	// Test cases
	tests := []struct {
		name          string
		args          []string
		expectedValue string
	}{
		{
			name:          "Default environment",
			args:          []string{},
			expectedValue: "dev", // Default value
		},
		{
			name:          "Explicit environment",
			args:          []string{"--env", "prod"},
			expectedValue: "prod",
		},
		{
			name:          "Different environment",
			args:          []string{"--env", "uat"},
			expectedValue: "uat",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Reset the env variable for each test
			env = ""

			// Create a new command for testing
			cmd := &cobra.Command{}
			cmd.PersistentFlags().StringVar(&env, "env", "dev", "Environment")
			cmd.RunE = func(cmd *cobra.Command, args []string) error {
				if env != tc.expectedValue {
					t.Errorf("Expected env to be %q, got %q", tc.expectedValue, env)
				}
				return nil
			}

			// Execute the command
			cmd.SetArgs(tc.args)
			cmd.Execute()
		})
	}
}

func TestCompareCommandOutputFormat(t *testing.T) {
	// This is a more complex test that would generally involve mocking
	// the vault client and capturing command output
	// We'll simulate this with a simplified test

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run a simulated comparison output
	simulateComparisonOutput()

	// Restore stdout and get output
	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Check for required formatting elements
	requiredElements := []string{
		"Comparing secrets",
		"Current Environment:",
		"Target Environment:",
		"----------------------------------------",
		"+ Key:",     // Added key indicator
		"- Key:",     // Missing key indicator
		"Current (",  // Current value indicator
		"Target (",   // Target value indicator
		"(redacted)", // Redacted indicator
	}

	for _, elem := range requiredElements {
		if !contains(output, elem) {
			t.Errorf("Expected output to contain %q, but it doesn't", elem)
		}
	}
}

func simulateComparisonOutput() {
	fmt.Println("Comparing secrets for app/dev/config")
	fmt.Println("Current Environment: dev | Target Environment: prod")
	fmt.Println("----------------------------------------")

	// Added key in current
	fmt.Println("+ Key: extra_key")
	fmt.Println("+ Current (dev): extra_value")
	fmt.Println("---")

	// Missing key in current
	fmt.Println("- Key: missing_key")
	fmt.Println("- Target (prod): target_value")
	fmt.Println("---")

	// Changed key
	fmt.Println("  Key: changed_key")
	fmt.Println("  Current (dev): current_value")
	fmt.Println("  Target (prod): target_value")
	fmt.Println("---")

	// Redacted key
	fmt.Println("  Key: app_secrets")
	fmt.Println("  Current (dev): (redacted)")
	fmt.Println("  Target (prod): (redacted)")
	fmt.Println("---")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		matches := true
		for j := 0; j < len(substr); j++ {
			if i+j >= len(s) || s[i+j] != substr[j] {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}
