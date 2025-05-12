package awssecretsmanager

import (
	"fmt"
	"strings"

	"github.com/secretz/vault-promoter/pkg/config"
)

// InstanceComparisonResult holds the result of comparing secrets between two AWS Secrets Manager instances
type InstanceComparisonResult struct {
	SourcePath      string
	TargetPath      string
	SourceEnv       string
	TargetEnv       string
	Comparisons     []*SecretComparison
	SourceInstance  string
	TargetInstance  string
	MissingInSource []string
	MissingInTarget []string
}

// CompareAWSSecretInstances compares secrets between two AWS Secrets Manager instances
func CompareAWSSecretInstances(sourceInstanceName, targetInstanceName, configPath, sourceEnv, targetConfigPath, targetEnv string, configs *config.Configs) (*InstanceComparisonResult, error) {
	// If target env not specified, use the same as source
	if targetEnv == "" {
		targetEnv = sourceEnv
	}

	// If target config path not specified, use the same as source
	if targetConfigPath == "" {
		targetConfigPath = configPath
	}

	// Get source instance config
	sourceConfig, err := configs.GetEnvironmentConfig(sourceInstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get source instance config: %w", err)
	}

	// Get target instance config
	targetConfig, err := configs.GetEnvironmentConfig(targetInstanceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get target instance config: %w", err)
	}

	// Verify that both configs are for AWS Secrets Manager
	if sourceConfig.Store != "awssecretsmanager" {
		return nil, fmt.Errorf("source instance %s is not configured as AWS Secrets Manager", sourceInstanceName)
	}

	if targetConfig.Store != "awssecretsmanager" {
		return nil, fmt.Errorf("target instance %s is not configured as AWS Secrets Manager", targetInstanceName)
	}

	// Create source client
	sourceClient, err := NewClient(sourceConfig, configs)
	if err != nil {
		return nil, fmt.Errorf("failed to create source client: %w", err)
	}

	// Create target client
	targetClient, err := NewClient(targetConfig, configs)
	if err != nil {
		return nil, fmt.Errorf("failed to create target client: %w", err)
	}

	// Initialize result
	result := &InstanceComparisonResult{
		SourcePath:     configPath,
		TargetPath:     targetConfigPath,
		SourceEnv:      sourceEnv,
		TargetEnv:      targetEnv,
		SourceInstance: sourceInstanceName,
		TargetInstance: targetInstanceName,
	}

	// Try to get source secrets
	sourceSecret, sourceIsJSON, sourceErr := sourceClient.GetSecret(configPath)
	sourceExists := true
	if sourceErr != nil {
		if strings.Contains(sourceErr.Error(), "secret not found") {
			sourceExists = false
		} else {
			return nil, fmt.Errorf("failed to get source secrets: %w", sourceErr)
		}
	}

	// Try to get target secrets
	targetSecret, targetIsJSON, targetErr := targetClient.GetSecret(targetConfigPath)
	targetExists := true
	if targetErr != nil {
		if strings.Contains(targetErr.Error(), "secret not found") {
			targetExists = false
		} else {
			return nil, fmt.Errorf("failed to get target secrets: %w", targetErr)
		}
	}

	// If neither exists, return an error
	if !sourceExists && !targetExists {
		return nil, fmt.Errorf("secrets don't exist in both AWS Secrets Manager instances at paths %s and %s", configPath, targetConfigPath)
	}
	// When only one secret exists, we'll proceed with the comparison
	// treating the missing secret as empty

	// Create a comparison
	comparison := &SecretComparison{
		Path: configPath,
	}

	// Handle case where the secret exists only in target
	if !sourceExists {
		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "INFO",
			Current:    fmt.Sprintf("Secret doesn't exist in %s AWS Secrets Manager instance", sourceInstanceName),
			Target:     "",
			IsRedacted: false,
			Status:     "-",
		})

		result.MissingInSource = append(result.MissingInSource, configPath)

		// Add all target values
		for key, targetValue := range targetSecret {
			targetValueStr := fmt.Sprintf("%v", targetValue)
			redacted := targetClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			if targetClient.redactJSONVals {
				redactedJSON, isJSON := targetClient.TryParseAndRedactJSON(targetValueStr)
				if isJSON {
					targetValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
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
		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "INFO",
			Current:    "",
			Target:     fmt.Sprintf("Secret doesn't exist in %s AWS Secrets Manager instance", targetInstanceName),
			IsRedacted: false,
			Status:     "+",
		})

		result.MissingInTarget = append(result.MissingInTarget, configPath)

		// Add all source values
		for key, sourceValue := range sourceSecret {
			sourceValueStr := fmt.Sprintf("%v", sourceValue)
			redacted := sourceClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			if sourceClient.redactJSONVals {
				redactedJSON, isJSON := sourceClient.TryParseAndRedactJSON(sourceValueStr)
				if isJSON {
					sourceValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
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

	// Check if secrets are incompatible (one is JSON, one is not)
	if sourceIsJSON != targetIsJSON {
		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "INFO",
			Current:    fmt.Sprintf("Secret in %s is in %s format", sourceInstanceName, secretFormatName(sourceIsJSON)),
			Target:     fmt.Sprintf("Secret in %s is in %s format", targetInstanceName, secretFormatName(targetIsJSON)),
			IsRedacted: false,
			Status:     "*",
		})

		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "ERROR",
			Current:    "Incompatible secret types: one is JSON, the other is a string",
			Target:     "Cannot compare secrets with different formats",
			IsRedacted: false,
			Status:     "*",
		})

		result.Comparisons = append(result.Comparisons, comparison)
		return result, nil
	}

	// If both are simple strings, compare directly
	if !sourceIsJSON && !targetIsJSON {
		sourceValue, sourceHasValue := sourceSecret["value"]
		targetValue, targetHasValue := targetSecret["value"]

		if !sourceHasValue || !targetHasValue {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        "ERROR",
				Current:    "Invalid secret value structure",
				Target:     "Cannot compare secrets with invalid structure",
				IsRedacted: false,
				Status:     "*",
			})
			result.Comparisons = append(result.Comparisons, comparison)
			return result, nil
		}

		sourceValueStr := fmt.Sprintf("%v", sourceValue)
		targetValueStr := fmt.Sprintf("%v", targetValue)

		// Skip if values are identical
		if sourceValueStr == targetValueStr {
			// Add a message indicating no differences
			return result, nil
		}

		// Always redact secrets unless explicitly turned off
		redacted := sourceClient.redactSecrets

		// Generate diff only if not redacted
		diffText := ""
		if !redacted {
			diffText = GenerateDiff(sourceValueStr, targetValueStr)
		}

		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "value",
			Current:    sourceValueStr,
			Target:     targetValueStr,
			Diff:       diffText,
			IsRedacted: redacted,
			Status:     "*", // Modified value
		})

		result.Comparisons = append(result.Comparisons, comparison)
		return result, nil
	}

	// Both secrets exist and are JSON, compare them
	processedKeys := make(map[string]bool)

	for key, sourceValue := range sourceSecret {
		processedKeys[key] = true
		targetValue, exists := targetSecret[key]
		if !exists {
			sourceValueStr := fmt.Sprintf("%v", sourceValue)
			redacted := sourceClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			if sourceClient.redactJSONVals {
				redactedJSON, isJSON := sourceClient.TryParseAndRedactJSON(sourceValueStr)
				if isJSON {
					sourceValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    sourceValueStr,
				Target:     "",
				IsRedacted: redacted,
				Status:     "+",
			})
			continue
		}

		currentValueStr := fmt.Sprintf("%v", sourceValue)
		targetValueStr := fmt.Sprintf("%v", targetValue)

		redacted := sourceClient.isRedactedKey(key)

		// Check if values are JSON and should be redacted
		if sourceClient.redactJSONVals {
			redactedCurrentJSON, isCurrentJSON := sourceClient.TryParseAndRedactJSON(currentValueStr)
			if isCurrentJSON {
				currentValueStr = redactedCurrentJSON
			}

			redactedTargetJSON, isTargetJSON := targetClient.TryParseAndRedactJSON(targetValueStr)
			if isTargetJSON {
				targetValueStr = redactedTargetJSON
			}
		}

		if currentValueStr != targetValueStr {
			// Generate diff only if not redacted
			diffText := ""
			if !redacted {
				diffText = GenerateDiff(currentValueStr, targetValueStr)
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    currentValueStr,
				Target:     targetValueStr,
				Diff:       diffText,
				IsRedacted: redacted,
				Status:     "*", // Modified value
			})
		}
	}

	for key, targetValue := range targetSecret {
		if _, exists := processedKeys[key]; !exists {
			targetValueStr := fmt.Sprintf("%v", targetValue)
			redacted := targetClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			if targetClient.redactJSONVals {
				redactedJSON, isJSON := targetClient.TryParseAndRedactJSON(targetValueStr)
				if isJSON {
					targetValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
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

// secretFormatName returns a human-readable name for the secret format
func secretFormatName(isJSON bool) string {
	if isJSON {
		return "JSON"
	}
	return "string"
}
