package comparison

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secretz/vault-promoter/pkg/awssecretsmanager"
	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
	"github.com/sergi/go-diff/diffmatchpatch"
)

// CrossStoreComparisonResult holds the result of comparing secrets between different store types
type CrossStoreComparisonResult struct {
	SourcePath      string
	TargetPath      string
	SourceEnv       string
	TargetEnv       string
	SourceInstance  string
	TargetInstance  string
	SourceStoreType string
	TargetStoreType string
	Comparisons     []*ComparisonItem
	MissingInSource []string
	MissingInTarget []string
}

// ComparisonItem represents a comparison between two secrets
type ComparisonItem struct {
	Path  string
	Diffs []DiffItem
}

// DiffItem represents a difference between two secrets
type DiffItem struct {
	Key        string
	Current    string
	Target     string
	Diff       string
	IsRedacted bool
	Status     string // +, -, or * for added, removed, or modified
}

// CompareVaultWithAWS compares secrets between Vault and AWS Secrets Manager
func CompareVaultWithAWS(
	sourceInstanceName, targetInstanceName, sourcePath, targetPath string,
	sourceEnv, targetEnv, sourceKV string,
	configs *config.Configs,
) (*CrossStoreComparisonResult, error) {
	// Get source and target configs
	sourceConfig, err := configs.GetEnvironmentConfig(sourceInstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get source instance config: %w", err)
	}

	targetConfig, err := configs.GetEnvironmentConfig(targetInstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get target instance config: %w", err)
	}

	// Check store types
	sourceStoreType := sourceConfig.Store
	targetStoreType := targetConfig.Store

	// Initialize result
	result := &CrossStoreComparisonResult{
		SourcePath:      sourcePath,
		TargetPath:      targetPath,
		SourceEnv:       sourceEnv,
		TargetEnv:       targetEnv,
		SourceInstance:  sourceInstanceName,
		TargetInstance:  targetInstanceName,
		SourceStoreType: sourceStoreType,
		TargetStoreType: targetStoreType,
	}

	// Verify that one store is Vault and the other is AWS Secrets Manager
	if !(sourceStoreType == "vault" && targetStoreType == "awssecretsmanager") &&
		!(sourceStoreType == "awssecretsmanager" && targetStoreType == "vault") {
		return nil, fmt.Errorf("cross-store comparison only supports Vault and AWS Secrets Manager")
	}

	// Retrieve secrets from source and target
	var sourceDataMap map[string]interface{}
	var targetDataMap map[string]interface{}
	var sourceExists, targetExists bool

	// Get source secrets
	if sourceStoreType == "vault" {
		// Create Vault client
		vaultClient, err := vault.NewClient(sourceConfig, configs, vault.Environment(sourceEnv), sourceKV)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %w", err)
		}

		// Get secrets from Vault
		secret, err := vaultClient.GetSecret(sourcePath)
		sourceExists = true
		if err != nil {
			if strings.Contains(err.Error(), "secret not found") {
				sourceExists = false
			} else {
				return nil, fmt.Errorf("failed to get source secrets: %w", err)
			}
		} else {
			sourceDataMap = secret.Data
		}
	} else {
		// Create AWS Secrets Manager client
		awsClient, err := awssecretsmanager.NewClient(sourceConfig, configs)
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS client: %w", err)
		}

		// Get secrets from AWS Secrets Manager
		data, isJSON, err := awsClient.GetSecret(sourcePath)
		sourceExists = true
		if err != nil {
			if strings.Contains(err.Error(), "secret not found") {
				sourceExists = false
			} else {
				return nil, fmt.Errorf("failed to get source secrets: %w", err)
			}
		} else {
			if !isJSON {
				// Cross-store comparison only works with JSON formatted secrets
				return nil, fmt.Errorf("AWS Secrets Manager secret must be in JSON format for cross-store comparison")
			}
			sourceDataMap = data
		}
	}

	// Get target secrets
	if targetStoreType == "vault" {
		// Create Vault client (we need to determine the kv engine from the config)
		vaultClient, err := vault.NewClient(targetConfig, configs, vault.Environment(targetEnv), sourceKV) // Assume same KV engine
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %w", err)
		}

		// Get secrets from Vault
		secret, err := vaultClient.GetSecret(targetPath)
		targetExists = true
		if err != nil {
			if strings.Contains(err.Error(), "secret not found") {
				targetExists = false
			} else {
				return nil, fmt.Errorf("failed to get target secrets: %w", err)
			}
		} else {
			targetDataMap = secret.Data
		}
	} else {
		// Create AWS Secrets Manager client
		awsClient, err := awssecretsmanager.NewClient(targetConfig, configs)
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS client: %w", err)
		}

		// Get secrets from AWS Secrets Manager
		data, isJSON, err := awsClient.GetSecret(targetPath)
		targetExists = true
		if err != nil {
			if strings.Contains(err.Error(), "secret not found") {
				targetExists = false
			} else {
				return nil, fmt.Errorf("failed to get target secrets: %w", err)
			}
		} else {
			if !isJSON {
				// Cross-store comparison only works with JSON formatted secrets
				return nil, fmt.Errorf("AWS Secrets Manager secret must be in JSON format for cross-store comparison")
			}
			targetDataMap = data
		}
	}

	// If neither exists, return an error
	if !sourceExists && !targetExists {
		return nil, fmt.Errorf("secrets don't exist in both stores at paths %s and %s", sourcePath, targetPath)
	}
	// When only one secret exists, we'll proceed with the comparison
	// treating the missing secret as empty

	// Create a comparison
	comparison := &ComparisonItem{
		Path: sourcePath,
	}

	// Handle case where the secret exists only in target
	if !sourceExists {
		comparison.Diffs = append(comparison.Diffs, DiffItem{
			Key:        "INFO",
			Current:    fmt.Sprintf("Secret doesn't exist in %s (%s)", sourceInstanceName, sourceStoreType),
			Target:     "",
			IsRedacted: false,
			Status:     "-",
		})

		result.MissingInSource = append(result.MissingInSource, sourcePath)

		// Add all target values with redaction
		for key, targetValue := range targetDataMap {
			targetValueStr := fmt.Sprintf("%v", targetValue)

			// Apply redaction logic
			redacted := shouldRedact(key, configs)

			// Check if value is JSON and should be redacted
			if configs.ShouldRedactJSONValues() {
				redactedJSON, isJSON := tryParseAndRedactJSON(targetValueStr, configs)
				if isJSON {
					targetValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, DiffItem{
				Key:        key,
				Current:    "", // No source value
				Target:     targetValueStr,
				IsRedacted: redacted,
				Status:     "-",
			})
		}

		result.Comparisons = append(result.Comparisons, comparison)
		return result, nil
	}

	// Handle case where the secret exists only in source
	if !targetExists {
		comparison.Diffs = append(comparison.Diffs, DiffItem{
			Key:        "INFO",
			Current:    "",
			Target:     fmt.Sprintf("Secret doesn't exist in %s (%s)", targetInstanceName, targetStoreType),
			IsRedacted: false,
			Status:     "+",
		})

		result.MissingInTarget = append(result.MissingInTarget, targetPath)

		// Add all source values with redaction
		for key, sourceValue := range sourceDataMap {
			sourceValueStr := fmt.Sprintf("%v", sourceValue)

			// Apply redaction logic
			redacted := shouldRedact(key, configs)

			// Check if value is JSON and should be redacted
			if configs.ShouldRedactJSONValues() {
				redactedJSON, isJSON := tryParseAndRedactJSON(sourceValueStr, configs)
				if isJSON {
					sourceValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, DiffItem{
				Key:        key,
				Current:    sourceValueStr,
				Target:     "", // No target value
				IsRedacted: redacted,
				Status:     "+",
			})
		}

		result.Comparisons = append(result.Comparisons, comparison)
		return result, nil
	}

	// Both secrets exist, compare them
	processedKeys := make(map[string]bool)

	for key, sourceValue := range sourceDataMap {
		processedKeys[key] = true
		targetValue, exists := targetDataMap[key]
		if !exists {
			sourceValueStr := fmt.Sprintf("%v", sourceValue)

			// Apply redaction logic
			redacted := shouldRedact(key, configs)

			// Check if value is JSON and should be redacted
			if configs.ShouldRedactJSONValues() {
				redactedJSON, isJSON := tryParseAndRedactJSON(sourceValueStr, configs)
				if isJSON {
					sourceValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, DiffItem{
				Key:        key,
				Current:    sourceValueStr,
				Target:     "",
				IsRedacted: redacted,
				Status:     "+",
			})
			continue
		}

		sourceValueStr := fmt.Sprintf("%v", sourceValue)
		targetValueStr := fmt.Sprintf("%v", targetValue)

		// Apply redaction logic
		redacted := shouldRedact(key, configs)

		// Check if values are JSON and should be redacted
		if configs.ShouldRedactJSONValues() {
			redactedSourceJSON, isSourceJSON := tryParseAndRedactJSON(sourceValueStr, configs)
			if isSourceJSON {
				sourceValueStr = redactedSourceJSON
			}

			redactedTargetJSON, isTargetJSON := tryParseAndRedactJSON(targetValueStr, configs)
			if isTargetJSON {
				targetValueStr = redactedTargetJSON
			}
		}

		if sourceValueStr != targetValueStr {
			// Generate diff only if not redacted
			diffText := ""
			if !redacted {
				diffText = generateDiff(sourceValueStr, targetValueStr)
			}

			comparison.Diffs = append(comparison.Diffs, DiffItem{
				Key:        key,
				Current:    sourceValueStr,
				Target:     targetValueStr,
				Diff:       diffText,
				IsRedacted: redacted,
				Status:     "*", // Modified value
			})
		}
	}

	for key, targetValue := range targetDataMap {
		if _, exists := processedKeys[key]; !exists {
			targetValueStr := fmt.Sprintf("%v", targetValue)

			// Apply redaction logic
			redacted := shouldRedact(key, configs)

			// Check if value is JSON and should be redacted
			if configs.ShouldRedactJSONValues() {
				redactedJSON, isJSON := tryParseAndRedactJSON(targetValueStr, configs)
				if isJSON {
					targetValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, DiffItem{
				Key:        key,
				Current:    "",
				Target:     targetValueStr,
				IsRedacted: redacted,
				Status:     "-",
			})
		}
	}

	// Only add the comparison if there are differences
	if len(comparison.Diffs) > 0 {
		result.Comparisons = append(result.Comparisons, comparison)
	}

	return result, nil
}

// Helper functions

// shouldRedact determines if a key should be redacted
func shouldRedact(key string, configs *config.Configs) bool {
	// AWS Secrets Manager secrets are all redacted by default
	if configs.ShouldRedactSecrets() {
		return true
	}

	// If redaction is disabled, check if this specific key should be redacted
	key = strings.ToLower(key)
	for _, redactedKey := range configs.GetRedactedKeys() {
		if strings.Contains(key, strings.ToLower(redactedKey)) {
			return true
		}
	}

	return false
}

// tryParseAndRedactJSON attempts to parse and redact a JSON string
func tryParseAndRedactJSON(value string, configs *config.Configs) (string, bool) {
	// Verify it's valid JSON
	if !isJSONValue(value) {
		return value, false
	}

	var data interface{}
	err := json.Unmarshal([]byte(value), &data)
	if err != nil {
		return value, false
	}

	// Redact JSON values
	redactedData := redactJSONValues(data, configs)

	// Check if anything changed
	redactedJSON, err := json.MarshalIndent(redactedData, "", "  ")
	if err != nil {
		return value, false
	}

	return string(redactedJSON), true
}

// isJSONValue checks if a string is a valid JSON object or array
func isJSONValue(s string) bool {
	var js interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}

// redactJSONValues recursively redacts sensitive values in JSON data
func redactJSONValues(data interface{}, configs *config.Configs) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// Process each key in the map
		result := make(map[string]interface{})
		for key, value := range v {
			// Check if this key should be redacted
			if shouldRedact(key, configs) {
				result[key] = "(redacted)"
			} else {
				// Recursively process nested values
				result[key] = redactJSONValues(value, configs)
			}
		}
		return result

	case []interface{}:
		// Process each item in the array
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = redactJSONValues(item, configs)
		}
		return result

	default:
		// Return primitive values as is
		return v
	}
}

// generateDiff creates a text diff between two strings
func generateDiff(current, target string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(current, target, false)
	return dmp.DiffPrettyText(diffs)
}
