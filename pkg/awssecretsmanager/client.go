package awssecretsmanager

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/sergi/go-diff/diffmatchpatch"
)

// Client handles interactions with AWS Secrets Manager
type Client struct {
	svc            *secretsmanager.SecretsManager
	redactedKeys   []string
	redactSecrets  bool // Default to true for AWS Secrets Manager
	redactJSONVals bool
}

// SecretDiff tracks changes between secret versions for auditing
type SecretDiff struct {
	Key        string
	Current    string
	Target     string
	Diff       string
	IsRedacted bool
	Status     string // +, -, or * for added, removed, or modified
}

// SecretComparison provides a structured view of differences for review
type SecretComparison struct {
	Path  string
	Diffs []SecretDiff
}

// NewClient initializes connection with proper IAM role and settings
func NewClient(envConfig *config.EnvironmentConfig, configs *config.Configs) (*Client, error) {
	// Validate config
	if envConfig.Role == "" {
		return nil, fmt.Errorf("AWS IAM role ARN is required for AWS Secrets Manager")
	}

	// Create AWS session
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	// Assume role if needed
	creds := stscreds.NewCredentials(sess, envConfig.Role)

	// Create Secrets Manager client
	svc := secretsmanager.New(sess, &aws.Config{
		Credentials: creds,
	})

	return &Client{
		svc:            svc,
		redactedKeys:   configs.GetRedactedKeys(),
		redactSecrets:  configs.ShouldRedactSecrets(),
		redactJSONVals: configs.ShouldRedactJSONValues(),
	}, nil
}

// GetSecret fetches and parses secret data with format detection
func (c *Client) GetSecret(path string) (map[string]interface{}, bool, error) {
	// Get the secret value
	result, err := c.svc.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(path),
	})

	if err != nil {
		// Check if the error is because the secret doesn't exist
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			return nil, false, fmt.Errorf("secret not found: %s", path)
		}
		return nil, false, fmt.Errorf("failed to get secret: %w", err)
	}

	var secretString string
	if result.SecretString != nil {
		secretString = *result.SecretString
	} else {
		return nil, false, fmt.Errorf("binary secrets not supported")
	}

	// Try to parse as JSON
	var secretData map[string]interface{}
	err = json.Unmarshal([]byte(secretString), &secretData)
	if err != nil {
		// Not a JSON object, return as a single value
		return map[string]interface{}{
			"value": secretString,
		}, false, nil
	}

	// It's a valid JSON
	return secretData, true, nil
}

// CompareSecretPaths identifies differences for review before copying
func (c *Client) CompareSecretPaths(sourcePath, targetPath string) (*SecretComparison, error) {
	// Get the source secrets
	sourceSecrets, sourceIsJSON, err := c.GetSecret(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get source secrets: %w", err)
	}

	// Get the target secrets
	targetSecrets, targetIsJSON, err := c.GetSecret(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get target secrets: %w", err)
	}

	// Check if both secrets are in the same format (JSON or non-JSON)
	if sourceIsJSON != targetIsJSON {
		return nil, fmt.Errorf("incompatible secret types: one is JSON, the other is a string")
	}

	// Create a comparison object
	comparison := &SecretComparison{
		Path:  sourcePath,
		Diffs: []SecretDiff{},
	}

	// If both are simple strings, compare directly
	if !sourceIsJSON && !targetIsJSON {
		sourceValue := fmt.Sprintf("%v", sourceSecrets["value"])
		targetValue := fmt.Sprintf("%v", targetSecrets["value"])

		// Skip if values are identical
		if sourceValue == targetValue {
			return comparison, nil
		}

		// Always redact for AWS Secrets Manager unless explicitly disabled
		redacted := c.redactSecrets

		// Generate diff only if not redacted
		diffText := ""
		if !redacted {
			diffText = GenerateDiff(sourceValue, targetValue)
		}

		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "value",
			Current:    sourceValue,
			Target:     targetValue,
			Diff:       diffText,
			IsRedacted: redacted,
			Status:     "*", // Modified value
		})

		return comparison, nil
	}

	// Track processed keys to avoid duplicates
	processedKeys := make(map[string]bool)

	// Compare JSON objects
	for key, currentValue := range sourceSecrets {
		processedKeys[key] = true

		// Convert value to string for comparison
		currentValueStr := fmt.Sprintf("%v", currentValue)

		// Check if the key exists in target secrets
		targetValue, exists := targetSecrets[key]
		if !exists {
			// Key only exists in current secrets (added)
			// Check if the key should be redacted
			redacted := c.isRedactedKey(key)

			// Try to parse and redact JSON values if needed
			if c.redactJSONVals {
				redactedJSON, isJSON := c.TryParseAndRedactJSON(currentValueStr)
				if isJSON {
					currentValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    currentValueStr,
				Target:     "",
				IsRedacted: redacted,
				Status:     "+", // Added key
			})
		} else {
			// Key exists in both, compare values
			targetValueStr := fmt.Sprintf("%v", targetValue)

			// Skip if values are identical
			if currentValueStr == targetValueStr {
				continue
			}

			// Check if the key should be redacted
			redacted := c.isRedactedKey(key)

			// Try to parse and redact JSON values if needed
			if c.redactJSONVals {
				redactedCurrentJSON, isCurrentJSON := c.TryParseAndRedactJSON(currentValueStr)
				if isCurrentJSON {
					currentValueStr = redactedCurrentJSON
				}

				redactedTargetJSON, isTargetJSON := c.TryParseAndRedactJSON(targetValueStr)
				if isTargetJSON {
					targetValueStr = redactedTargetJSON
				}
			}

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

	// Find keys that only exist in target secrets (removed)
	for key, targetValue := range targetSecrets {
		if _, exists := processedKeys[key]; !exists {
			// Key only exists in target secrets (removed)
			targetValueStr := fmt.Sprintf("%v", targetValue)

			// Check if the key should be redacted
			redacted := c.isRedactedKey(key)

			// Try to parse and redact JSON values if needed
			if c.redactJSONVals {
				redactedJSON, isJSON := c.TryParseAndRedactJSON(targetValueStr)
				if isJSON {
					targetValueStr = redactedJSON
				}
			}

			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    "",
				Target:     targetValueStr,
				IsRedacted: redacted,
				Status:     "-", // Removed key
			})
		}
	}

	return comparison, nil
}

// isRedactedKey determines which values need protection in logs and output
func (c *Client) isRedactedKey(key string) bool {
	// By default, all values in AWS Secrets Manager are considered secrets
	if c.redactSecrets {
		return true
	}

	// If redaction is disabled, check if this specific key should be redacted
	key = strings.ToLower(key)
	for _, redactedKey := range c.redactedKeys {
		if strings.Contains(key, strings.ToLower(redactedKey)) {
			return true
		}
	}

	return false
}

// IsJSONValue helps identify nested structures that need special handling
func IsJSONValue(s string) bool {
	var js interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}

// RedactJSONValues ensures sensitive data in nested structures is protected
func (c *Client) RedactJSONValues(data interface{}) interface{} {
	// Redact based on type
	switch v := data.(type) {
	case map[string]interface{}:
		// Process each key in the map
		result := make(map[string]interface{})
		for key, value := range v {
			// Check if this key should be redacted
			if c.isRedactedKey(key) {
				result[key] = "(redacted)"
			} else {
				// Recursively process nested values
				result[key] = c.RedactJSONValues(value)
			}
		}
		return result

	case []interface{}:
		// Process each item in the array
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = c.RedactJSONValues(item)
		}
		return result

	default:
		// Return primitive values as is
		return v
	}
}

// TryParseAndRedactJSON handles potential JSON strings that might contain sensitive data
func (c *Client) TryParseAndRedactJSON(value string) (string, bool) {
	if !IsJSONValue(value) {
		return value, false
	}

	var data interface{}
	err := json.Unmarshal([]byte(value), &data)
	if err != nil {
		return value, false
	}

	redactedData := c.RedactJSONValues(data)
	if reflect.DeepEqual(data, redactedData) {
		return value, false
	}

	redactedJSON, err := json.MarshalIndent(redactedData, "", "  ")
	if err != nil {
		return value, false
	}

	return string(redactedJSON), true
}

// GenerateDiff provides visual representation of changes for review
func GenerateDiff(current, target string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(current, target, false)
	return dmp.DiffPrettyText(diffs)
}
