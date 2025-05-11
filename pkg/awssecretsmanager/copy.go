package awssecretsmanager

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/secretz/vault-promoter/pkg/config"
)

// CopyOptions represents options for copying secrets
type CopyOptions struct {
	Overwrite    bool
	CopyConfig   bool
	CopySecrets  bool
	OnlyCopyKeys bool
}

// CopySecret copies a secret from one path to another within AWS Secrets Manager
func (c *Client) CopySecret(sourcePath, targetPath string, options CopyOptions, configs *config.Configs) error {
	// Get the source secret
	sourceData, isJSON, err := c.GetSecret(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to get source secret: %w", err)
	}

	// Check if the target secret exists
	targetExists := true
	targetData, targetIsJSON, err := c.GetSecret(targetPath)
	if err != nil {
		if strings.Contains(err.Error(), "secret not found") {
			targetExists = false
			// Initialize an empty target data map
			targetData = make(map[string]interface{})
			targetIsJSON = isJSON // Match the format of the source
		} else {
			return fmt.Errorf("failed to get target secret: %w", err)
		}
	}

	// If source is not JSON, we can only copy to another AWS Secrets Manager
	if !isJSON {
		// For non-JSON secrets, just copy the value directly
		value := sourceData["value"]
		valueStr := fmt.Sprintf("%v", value)

		// Apply redaction if needed
		if c.redactSecrets && !options.CopySecrets {
			valueStr = "" // Redact the entire value
		}

		// Create or update the target secret
		if targetExists {
			_, err = c.svc.UpdateSecret(&secretsmanager.UpdateSecretInput{
				SecretId:     aws.String(targetPath),
				SecretString: aws.String(valueStr),
			})
		} else {
			_, err = c.svc.CreateSecret(&secretsmanager.CreateSecretInput{
				Name:         aws.String(targetPath),
				SecretString: aws.String(valueStr),
			})
		}

		if err != nil {
			return fmt.Errorf("failed to update target secret: %w", err)
		}

		return nil
	}

	// For JSON secrets, copy each key-value pair
	resultData := make(map[string]interface{})

	// If target exists, start with the target data
	if targetExists && targetIsJSON {
		for k, v := range targetData {
			resultData[k] = v
		}
	}

	// Copy values from source to target
	for key, value := range sourceData {
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

	// Convert the result data to JSON
	jsonData, err := json.Marshal(resultData)
	if err != nil {
		return fmt.Errorf("failed to marshal target data: %w", err)
	}

	// Create or update the target secret
	if targetExists {
		_, err = c.svc.UpdateSecret(&secretsmanager.UpdateSecretInput{
			SecretId:     aws.String(targetPath),
			SecretString: aws.String(string(jsonData)),
		})
	} else {
		_, err = c.svc.CreateSecret(&secretsmanager.CreateSecretInput{
			Name:         aws.String(targetPath),
			SecretString: aws.String(string(jsonData)),
		})
	}

	if err != nil {
		return fmt.Errorf("failed to update target secret: %w", err)
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
