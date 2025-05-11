package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// CopyOptions represents options for copying secrets
type CopyOptions struct {
	Overwrite    bool
	CopyConfig   bool
	CopySecrets  bool
	OnlyCopyKeys bool
}

// EnsureKVEngineExists ensures that the KV engine exists in Vault
func (c *Client) EnsureKVEngineExists(kvEngine string) error {
	// Check if KV engine exists
	mountOutput, err := c.Sys().ListMounts()
	if err != nil {
		return fmt.Errorf("failed to list vault mounts: %w", err)
	}

	// Ensure the KV engine exists and has a trailing slash
	kvEnginePath := kvEngine
	if !strings.HasSuffix(kvEnginePath, "/") {
		kvEnginePath += "/"
	}

	// Check if the engine exists
	if _, exists := mountOutput[kvEnginePath]; !exists {
		// Create the KV engine if it doesn't exist
		options := &vault.MountInput{
			Type:    "kv",
			Options: map[string]string{"version": "2"},
		}

		err := c.Sys().Mount(kvEnginePath, options)
		if err != nil {
			return fmt.Errorf("failed to create KV engine '%s': %w", kvEngine, err)
		}
	}

	return nil
}

// CopySecret copies a secret from one path to another within Vault
func (c *Client) CopySecret(sourcePath, targetPath string, options CopyOptions) error {
	// Get the source secret
	sourceSecret, err := c.GetSecret(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to get source secret: %w", err)
	}

	// Check if the target secret exists
	targetExists := true
	targetSecret, err := c.GetSecret(targetPath)
	if err != nil {
		if strings.Contains(err.Error(), "secret not found") {
			targetExists = false
			// Initialize an empty target data map
			targetSecret = &vault.KVSecret{
				Data: make(map[string]interface{}),
			}
		} else {
			return fmt.Errorf("failed to get target secret: %w", err)
		}
	}

	// Prepare the data to be written
	resultData := make(map[string]interface{})

	// If target exists, start with the target data
	if targetExists {
		for k, v := range targetSecret.Data {
			resultData[k] = v
		}
	}

	// Copy values from source to target
	for key, value := range sourceSecret.Data {
		// Skip if the key already exists in target and we're not overwriting
		if _, exists := resultData[key]; exists && !options.Overwrite {
			continue
		}

		// Check if this is a config or secret key
		isRedactedKey := c.isRedactedKey(key)

		// Skip based on options
		if isRedactedKey && !options.CopySecrets && !options.CopyConfig {
			continue
		}

		if !isRedactedKey && options.CopySecrets && !options.CopyConfig {
			continue
		}

		// Convert to string for processing
		valueStr := fmt.Sprintf("%v", value)

		// Handle JSON values if needed
		if c.redactJSONVals && IsJSONValue(valueStr) {
			var jsonData interface{}
			if err := json.Unmarshal([]byte(valueStr), &jsonData); err == nil {
				if options.OnlyCopyKeys {
					// Only copy the keys, not the values
					jsonData = extractJSONStructure(jsonData)
				} else if isRedactedKey && !options.CopySecrets {
					// Redact the values
					jsonData = c.RedactJSONValues(jsonData)
				}

				// Convert back to string
				jsonBytes, err := json.Marshal(jsonData)
				if err == nil {
					valueStr = string(jsonBytes)
				}
			}
		} else if options.OnlyCopyKeys || (isRedactedKey && !options.CopySecrets && c.redactSecrets) {
			// For non-JSON values, redact if needed
			valueStr = ""
		}

		// Add to result data
		resultData[key] = valueStr
	}

	// Write the data to the target path
	_, err = c.KVv2(c.kvEngine).Put(context.Background(), targetPath, resultData)
	if err != nil {
		return fmt.Errorf("failed to write target secret: %w", err)
	}

	return nil
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
