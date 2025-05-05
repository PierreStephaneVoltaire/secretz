package vault

import (
	"fmt"
	"strings"

	"github.com/secretz/vault-promoter/pkg/config"
)

// InstanceComparisonResult holds the result of comparing secrets between two Vault instances
type InstanceComparisonResult struct {
	SourcePath      string
	TargetPath      string
	SourceEnv       string
	TargetEnv       string
	SourceKVEngine  string
	TargetKVEngine  string
	Comparisons     []*SecretComparison
	SourceInstance  string
	TargetInstance  string
	MissingInSource []string
	MissingInTarget []string
}

// CompareVaultInstances compares secrets between two Vault instances
func CompareVaultInstances(sourceInstanceName, targetInstanceName, configPath, sourceEnv, kvEngine, targetConfigPath, targetEnv, targetKVEngine string, configs *config.Configs) (*InstanceComparisonResult, error) {
	// If target env not specified, use the same as source
	if targetEnv == "" {
		targetEnv = sourceEnv
	}

	// If target KV engine not specified, use the same as source
	if targetKVEngine == "" {
		targetKVEngine = kvEngine
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

	// Create source client
	sourceClient, err := NewClient(sourceConfig, configs, Environment(sourceEnv), kvEngine)
	if err != nil {
		return nil, fmt.Errorf("failed to create source client: %w", err)
	}

	// Create target client
	targetClient, err := NewClient(targetConfig, configs, Environment(targetEnv), targetKVEngine)
	if err != nil {
		return nil, fmt.Errorf("failed to create target client: %w", err)
	}

	// Initialize result
	result := &InstanceComparisonResult{
		SourcePath:     configPath,
		TargetPath:     targetConfigPath,
		SourceEnv:      sourceEnv,
		TargetEnv:      targetEnv,
		SourceKVEngine: kvEngine,
		TargetKVEngine: targetKVEngine,
		SourceInstance: sourceInstanceName,
		TargetInstance: targetInstanceName,
	}

	// Try to get source secrets
	sourceSecret, sourceErr := sourceClient.GetSecret(configPath)
	sourceExists := true
	if sourceErr != nil {
		if strings.Contains(sourceErr.Error(), "secret not found") {
			sourceExists = false
		} else {
			return nil, fmt.Errorf("failed to get source secrets: %w", sourceErr)
		}
	}

	// Try to get target secrets
	targetSecret, targetErr := targetClient.GetSecret(targetConfigPath)
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
		return nil, fmt.Errorf("secrets don't exist in both vault instances at paths %s and %s", configPath, targetConfigPath)
	}

	// Create a comparison
	comparison := &SecretComparison{
		Path: configPath,
	}

	// Handle case where the secret exists only in target
	if !sourceExists {
		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "INFO",
			Current:    fmt.Sprintf("Secret doesn't exist in %s vault instance", sourceInstanceName),
			Target:     "",
			IsRedacted: false,
			Status:     "-",
		})

		result.MissingInSource = append(result.MissingInSource, configPath)

		// Add all target values
		for key, targetValue := range targetSecret.Data {
			targetValueStr := fmt.Sprintf("%v", targetValue)
			redacted := targetClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			redactedJSON, isJSON := targetClient.TryParseAndRedactJSON(targetValueStr)
			if isJSON {
				targetValueStr = redactedJSON
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
			Target:     fmt.Sprintf("Secret doesn't exist in %s vault instance", targetInstanceName),
			IsRedacted: false,
			Status:     "+",
		})

		result.MissingInTarget = append(result.MissingInTarget, configPath)

		// Add all source values
		for key, sourceValue := range sourceSecret.Data {
			sourceValueStr := fmt.Sprintf("%v", sourceValue)
			redacted := sourceClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			redactedJSON, isJSON := sourceClient.TryParseAndRedactJSON(sourceValueStr)
			if isJSON {
				sourceValueStr = redactedJSON
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

	// Both secrets exist, compare them
	processedKeys := make(map[string]bool)

	for key, sourceValue := range sourceSecret.Data {
		processedKeys[key] = true
		targetValue, exists := targetSecret.Data[key]
		if !exists {
			sourceValueStr := fmt.Sprintf("%v", sourceValue)
			redacted := sourceClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			redactedJSON, isJSON := sourceClient.TryParseAndRedactJSON(sourceValueStr)
			if isJSON {
				sourceValueStr = redactedJSON
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
		redactedCurrentJSON, isCurrentJSON := sourceClient.TryParseAndRedactJSON(currentValueStr)
		if isCurrentJSON {
			currentValueStr = redactedCurrentJSON
		}

		redactedTargetJSON, isTargetJSON := targetClient.TryParseAndRedactJSON(targetValueStr)
		if isTargetJSON {
			targetValueStr = redactedTargetJSON
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

	for key, targetValue := range targetSecret.Data {
		if _, exists := processedKeys[key]; !exists {
			targetValueStr := fmt.Sprintf("%v", targetValue)
			redacted := targetClient.isRedactedKey(key)

			// Check if value is JSON and should be redacted
			redactedJSON, isJSON := targetClient.TryParseAndRedactJSON(targetValueStr)
			if isJSON {
				targetValueStr = redactedJSON
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
