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
	Prune        bool // If true, keys not in source will be removed from target
}

// CopySecret handles secret transfer between paths
func (c *Client) CopySecret(sourcePath, targetPath string, options CopyOptions, configs *config.Configs) error {
	sourceData, isJSON, err := c.GetSecret(sourcePath)
	if err != nil {
		return fmt.Errorf("failed to get source secret: %w", err)
	}

	targetExists := true
	targetData, targetIsJSON, err := c.GetSecret(targetPath)
	if err != nil {
		if strings.Contains(err.Error(), "secret not found") {
			targetExists = false
			targetData = make(map[string]interface{})
			// Match the format of the source for consistency
			targetIsJSON = isJSON
		} else {
			return fmt.Errorf("failed to get target secret: %w", err)
		}
	}

	// Special handling for non-JSON secrets
	if !isJSON {
		value := sourceData["value"]
		valueStr := fmt.Sprintf("%v", value)

		// Redact if security settings require it
		if c.redactSecrets && !options.CopySecrets {
			valueStr = ""
		}

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

	resultData := make(map[string]interface{})

	// Start with existing target data unless pruning is enabled
	if targetExists && targetIsJSON && !options.Prune {
		for k, v := range targetData {
			resultData[k] = v
		}
	}

	// Process each source key according to options
	for key, value := range sourceData {
		// Skip existing keys if not overwriting
		if _, exists := resultData[key]; exists && !options.Overwrite {
			continue
		}

		isRedactedKey := c.isRedactedKey(key)

		// Filter keys based on copy options
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

// CopySecretData operates directly on in-memory data for better security
func (c *Client) CopySecretData(data map[string]interface{}, targetPath string, options CopyOptions, configs *config.Configs) error {
	targetExists := true
	targetData, targetIsJSON, err := c.GetSecret(targetPath)
	if err != nil {
		if strings.Contains(err.Error(), "secret not found") {
			targetExists = false
			targetData = make(map[string]interface{})
			// Always use JSON format for direct data operations
			targetIsJSON = true
		} else {
			return fmt.Errorf("failed to get target secret: %w", err)
		}
	}

	resultData := make(map[string]interface{})

	// Start with existing target data unless pruning is enabled
	if targetExists && targetIsJSON && !options.Prune {
		for k, v := range targetData {
			resultData[k] = v
		}
	}

	for key, value := range data {
		// Skip existing keys if not overwriting
		if _, exists := resultData[key]; exists && !options.Overwrite {
			continue
		}

		isRedactedKey := c.isRedactedKey(key)

		// Filter keys based on copy options
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

// extractJSONStructure preserves structure while removing sensitive values
func extractJSONStructure(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			switch value.(type) {
			case map[string]interface{}, []interface{}:
				// Preserve nested structure recursively
				result[key] = extractJSONStructure(value)
			default:
				result[key] = ""
			}
		}
		return result

	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = extractJSONStructure(item)
		}
		return result

	default:
		return ""
	}
}
