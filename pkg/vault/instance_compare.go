package vault

import (
	"fmt"
	"strings"

	"github.com/secretz/vault-promoter/pkg/config"
)

// InstanceComparisonResult holds the result of comparing secrets between two Vault instances
type InstanceComparisonResult struct {
	App             string
	Environment     string
	KVEngine        string
	PathSuffix      string
	Comparisons     []*SecretComparison
	SourceInstance  string
	TargetInstance  string
	MissingInSource []string
	MissingInTarget []string
}

// CompareVaultInstances compares secrets between two Vault instances
func CompareVaultInstances(sourceInstanceName, targetInstanceName, appName, environment, kvEngine, pathSuffix string, configs *config.Configs) (*InstanceComparisonResult, error) {
	// Validate path suffix
	validPaths := []string{"config", "configs", "secret", "secrets"}
	isValidPath := false
	for _, p := range validPaths {
		if p == pathSuffix {
			isValidPath = true
			break
		}
	}
	if !isValidPath {
		return nil, fmt.Errorf("invalid path suffix: %s, must be one of: config, configs, secret, secrets", pathSuffix)
	}

	// Validate environment values
	validEnv := false
	for _, e := range []Environment{EnvDev, EnvUAT, EnvProd} {
		if string(e) == environment {
			validEnv = true
			break
		}
	}
	if !validEnv {
		return nil, fmt.Errorf("invalid environment: %s, must be one of: dev, uat, prod", environment)
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
	sourceClient, err := NewClient(sourceConfig.URL, sourceConfig.Token, Environment(environment), kvEngine)
	if err != nil {
		return nil, fmt.Errorf("failed to create source client: %w", err)
	}

	// Create target client
	targetClient, err := NewClient(targetConfig.URL, targetConfig.Token, Environment(environment), kvEngine)
	if err != nil {
		return nil, fmt.Errorf("failed to create target client: %w", err)
	}

	// Initialize result
	result := &InstanceComparisonResult{
		App:            appName,
		Environment:    environment,
		KVEngine:       kvEngine,
		PathSuffix:     pathSuffix,
		SourceInstance: sourceInstanceName,
		TargetInstance: targetInstanceName,
	}

	// Path format: kv/app1/ENV/secret(s) or kv/app1/ENV/config(s)
	path := fmt.Sprintf("%s/%s/%s", appName, environment, pathSuffix)

	// Try to get source secrets
	sourceSecret, sourceErr := sourceClient.GetSecret(path)
	sourceExists := true
	if sourceErr != nil {
		if strings.Contains(sourceErr.Error(), "secret not found") {
			sourceExists = false
		} else {
			return nil, fmt.Errorf("failed to get source secrets: %w", sourceErr)
		}
	}

	// Try to get target secrets
	targetSecret, targetErr := targetClient.GetSecret(path)
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
		return nil, fmt.Errorf("secret %s doesn't exist in both vault instances", path)
	}

	// Create a comparison
	comparison := &SecretComparison{
		Path: path,
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

		result.MissingInSource = append(result.MissingInSource, path)

		// Add all target values
		for key, targetValue := range targetSecret.Data {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    "", // No source value
				Target:     fmt.Sprintf("%v", targetValue),
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
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

		result.MissingInTarget = append(result.MissingInTarget, path)

		// Add all source values
		for key, sourceValue := range sourceSecret.Data {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    fmt.Sprintf("%v", sourceValue),
				Target:     "", // No target value
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
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
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    fmt.Sprintf("%v", sourceValue),
				Target:     "",
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
				Status:     "+",
			})
			continue
		}

		sourceValueStr := fmt.Sprintf("%v", sourceValue)
		targetValueStr := fmt.Sprintf("%v", targetValue)

		if sourceValueStr != targetValueStr {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    sourceValueStr,
				Target:     targetValueStr,
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
				Status:     "*", // Modified value
			})
		}
	}

	for key, targetValue := range targetSecret.Data {
		if _, exists := processedKeys[key]; !exists {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    "",
				Target:     fmt.Sprintf("%v", targetValue),
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
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
