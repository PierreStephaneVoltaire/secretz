package comparison

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/secretz/vault-promoter/pkg/awssecretsmanager"
	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
)

// CopyOptions represents options for copying secrets
type CopyOptions struct {
	Overwrite    bool
	CopyConfig   bool
	CopySecrets  bool
	OnlyCopyKeys bool
}

// CopyResult represents the result of a copy operation
type CopyResult struct {
	SourcePath      string
	TargetPath      string
	SourceEnv       string
	TargetEnv       string
	SourceInstance  string
	TargetInstance  string
	SourceStoreType string
	TargetStoreType string
	Success         bool
	Message         string
	Keys            map[string]interface{} // Map of keys that were copied
}

// CopyVaultWithAWS copies secrets between Vault and AWS Secrets Manager
func CopyVaultWithAWS(
	sourceInstanceName, targetInstanceName, sourcePath, targetPath string,
	sourceEnv, targetEnv, sourceKV, targetKV string,
	configs *config.Configs,
	options CopyOptions,
) (*CopyResult, error) {
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
	result := &CopyResult{
		SourcePath:      sourcePath,
		TargetPath:      targetPath,
		SourceEnv:       sourceEnv,
		TargetEnv:       targetEnv,
		SourceInstance:  sourceInstanceName,
		TargetInstance:  targetInstanceName,
		SourceStoreType: sourceStoreType,
		TargetStoreType: targetStoreType,
		Success:         false,
	}

	// Verify that one store is Vault and the other is AWS Secrets Manager
	if !(sourceStoreType == "vault" && targetStoreType == "awssecretsmanager") &&
		!(sourceStoreType == "awssecretsmanager" && targetStoreType == "vault") {
		// Handle same store type copies
		if sourceStoreType == targetStoreType {
			switch sourceStoreType {
			case "vault":
				return copyWithinVault(sourceConfig, targetConfig, sourcePath, targetPath, sourceEnv, targetEnv, sourceKV, targetKV, configs, options)
			case "awssecretsmanager":
				return copyWithinAWS(sourceConfig, targetConfig, sourcePath, targetPath, configs, options)
			default:
				return nil, fmt.Errorf("unsupported store type: %s", sourceStoreType)
			}
		}
		return nil, fmt.Errorf("cross-store copy only supports Vault and AWS Secrets Manager")
	}

	// Retrieve secrets from source
	var sourceDataMap map[string]interface{}
	var isJSON bool

	// Get source secrets
	if sourceStoreType == "vault" {
		// Create Vault client
		vaultClient, err := vault.NewClient(sourceConfig, configs, vault.Environment(sourceEnv), sourceKV)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %w", err)
		}

		// Get secrets from Vault
		secret, err := vaultClient.GetSecret(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get source secrets: %w", err)
		}

		sourceDataMap = secret.Data
		isJSON = true // Vault secrets are always structured as JSON
	} else {
		// Create AWS Secrets Manager client
		awsClient, err := awssecretsmanager.NewClient(sourceConfig, configs)
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS client: %w", err)
		}

		// Get secrets from AWS Secrets Manager
		data, jsonFormat, err := awsClient.GetSecret(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get source secrets: %w", err)
		}

		sourceDataMap = data
		isJSON = jsonFormat

		// If source is AWS and not in JSON format, it can only be copied to another AWS instance
		if !isJSON && targetStoreType == "vault" {
			return nil, fmt.Errorf("cannot copy non-JSON AWS secret to Vault")
		}
	}

	// Create target client and copy the secret
	if targetStoreType == "vault" {
		// Create Vault client
		vaultClient, err := vault.NewClient(targetConfig, configs, vault.Environment(targetEnv), targetKV)
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault client: %w", err)
		}
		
		// Ensure the KV engine exists
		err = vaultClient.EnsureKVEngineExists(targetKV)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure KV engine exists: %w", err)
		}

		// Prepare data for Vault
		resultData := make(map[string]interface{})

		// Process each key-value pair
		for key, value := range sourceDataMap {
			// Convert to string for processing
			valueStr := fmt.Sprintf("%v", value)

			// Check if this is a redacted key
			redacted := shouldRedact(key, configs)

			// Handle JSON values if needed
			if configs.ShouldRedactJSONValues() && isJSONValue(valueStr) {
				var jsonData interface{}
				if err := json.Unmarshal([]byte(valueStr), &jsonData); err == nil {
					if options.OnlyCopyKeys {
						// Only copy the keys, not the values
						jsonData = extractJSONStructure(jsonData)
					} else if redacted && !options.CopySecrets {
						// Redact the values
						jsonData = redactJSONValues(jsonData, configs)
					}

					// Convert back to string
					jsonBytes, err := json.Marshal(jsonData)
					if err == nil {
						valueStr = string(jsonBytes)
					}
				}
			} else if options.OnlyCopyKeys || (redacted && !options.CopySecrets && configs.ShouldRedactSecrets()) {
				// For non-JSON values, redact if needed
				valueStr = ""
			}

			// Skip based on options
			if redacted && !options.CopySecrets && !options.CopyConfig {
				continue
			}

			if !redacted && options.CopySecrets && !options.CopyConfig {
				continue
			}

			// Add to result data
			resultData[key] = valueStr
		}

		// Write to Vault
		_, err = vaultClient.KVv2(targetKV).Put(context.Background(), targetPath, resultData)
		if err != nil {
			return nil, fmt.Errorf("failed to write target secret: %w", err)
		}
	} else {
		// Create AWS Secrets Manager client
		awsClient, err := awssecretsmanager.NewClient(targetConfig, configs)
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS client: %w", err)
		}

		// Convert Vault data to AWS format
		awsOptions := awssecretsmanager.CopyOptions{
			Overwrite:    options.Overwrite,
			CopyConfig:   options.CopyConfig,
			CopySecrets:  options.CopySecrets,
			OnlyCopyKeys: options.OnlyCopyKeys,
		}

		// Copy to AWS
		err = awsClient.CopySecret(sourcePath, targetPath, awsOptions, configs)
		if err != nil {
			return nil, fmt.Errorf("failed to copy to AWS Secrets Manager: %w", err)
		}
	}

	result.Success = true
	result.Message = fmt.Sprintf("Successfully copied secret from %s to %s", sourcePath, targetPath)
	return result, nil
}

// copyWithinVault copies secrets between two Vault instances
func copyWithinVault(
	sourceConfig, targetConfig *config.EnvironmentConfig,
	sourcePath, targetPath string,
	sourceEnv, targetEnv, sourceKV, targetKV string,
	configs *config.Configs,
	options CopyOptions,
) (*CopyResult, error) {
	result := &CopyResult{
		SourcePath:      sourcePath,
		TargetPath:      targetPath,
		SourceEnv:       sourceEnv,
		TargetEnv:       targetEnv,
		SourceStoreType: "vault",
		TargetStoreType: "vault",
		Success:         false,
	}

	// Create source Vault client
	sourceClient, err := vault.NewClient(sourceConfig, configs, vault.Environment(sourceEnv), sourceKV)
	if err != nil {
		return nil, fmt.Errorf("failed to create source Vault client: %w", err)
	}

	// Create target client
	targetClient, err := vault.NewClient(targetConfig, configs, vault.Environment(targetEnv), targetKV)
	if err != nil {
		return nil, fmt.Errorf("failed to create target Vault client: %w", err)
	}
	
	// Ensure the KV engine exists
	err = targetClient.EnsureKVEngineExists(targetKV)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure KV engine exists: %w", err)
	}

	// Check if source path exists
	_, err = sourceClient.GetSecret(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get source secret: %w", err)
	}

	// Check if source and target paths are the same and environments are the same
	if sourcePath == targetPath && sourceEnv == targetEnv && sourceConfig.URL == targetConfig.URL {
		return nil, fmt.Errorf("source and target are the same, cannot copy to self")
	}

	// Convert options
	vaultOptions := vault.CopyOptions{
		Overwrite:    options.Overwrite,
		CopyConfig:   options.CopyConfig,
		CopySecrets:  options.CopySecrets,
		OnlyCopyKeys: options.OnlyCopyKeys,
	}

	// Copy the secret
	err = targetClient.CopySecret(sourcePath, targetPath, vaultOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to copy secret: %w", err)
	}

	result.Success = true
	result.Message = fmt.Sprintf("Successfully copied secret from %s to %s", sourcePath, targetPath)
	return result, nil
}

// copyWithinAWS copies secrets between two AWS Secrets Manager instances
func copyWithinAWS(
	sourceConfig, targetConfig *config.EnvironmentConfig,
	sourcePath, targetPath string,
	configs *config.Configs,
	options CopyOptions,
) (*CopyResult, error) {
	result := &CopyResult{
		SourcePath:      sourcePath,
		TargetPath:      targetPath,
		SourceStoreType: "awssecretsmanager",
		TargetStoreType: "awssecretsmanager",
		Success:         false,
	}

	// Create source AWS client
	sourceClient, err := awssecretsmanager.NewClient(sourceConfig, configs)
	if err != nil {
		return nil, fmt.Errorf("failed to create source AWS client: %w", err)
	}
	
	// Check if source path exists
	_, err = sourceClient.GetSecret(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get source secret: %w", err)
	}

	// Create target AWS client
	targetClient, err := awssecretsmanager.NewClient(targetConfig, configs)
	if err != nil {
		return nil, fmt.Errorf("failed to create target AWS client: %w", err)
	}

	// Check if source and target are the same
	if sourcePath == targetPath && sourceConfig.Role == targetConfig.Role {
		return nil, fmt.Errorf("source and target are the same, cannot copy to self")
	}

	// Convert options
	awsOptions := awssecretsmanager.CopyOptions{
		Overwrite:    options.Overwrite,
		CopyConfig:   options.CopyConfig,
		CopySecrets:  options.CopySecrets,
		OnlyCopyKeys: options.OnlyCopyKeys,
	}

	// Copy the secret using the target client
	err = targetClient.CopySecret(sourcePath, targetPath, awsOptions, configs)
	if err != nil {
		return nil, fmt.Errorf("failed to copy secret: %w", err)
	}

	result.Success = true
	result.Message = fmt.Sprintf("Successfully copied secret from %s to %s", sourcePath, targetPath)
	return result, nil
}

// extractJSONStructure creates a copy of the JSON structure with empty values
func extractJSONStructure(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		// Process each key in the map
		result := make(map[string]interface{})
		for key, value := range v {
			switch value.(type) {
			case map[string]interface{}, []interface{}:
				// Recursively process nested structures
				result[key] = extractJSONStructure(value)
			default:
				// Replace primitive values with empty string
				result[key] = ""
			}
		}
		return result

	case []interface{}:
		// Process each item in the array
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = extractJSONStructure(item)
		}
		return result

	default:
		// Return empty string for primitive values
		return ""
	}
}
