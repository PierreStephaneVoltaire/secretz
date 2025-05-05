package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/sergi/go-diff/diffmatchpatch"
)

type Environment string

const (
	EnvDev  Environment = "dev"
	EnvUAT  Environment = "uat"
	EnvProd Environment = "prod"
)

type Client struct {
	*vault.Client
	env            Environment
	kvEngine       string
	redactedKeys   []string
	redactSecrets  bool
	redactJSONVals bool
}

type SecretDiff struct {
	Key        string
	Current    string
	Target     string
	Diff       string
	IsRedacted bool
	Status     string // +, -, or * for added, removed, or modified
}
type SecretComparison struct {
	Path  string
	Diffs []SecretDiff
}

func NewClient(envConfig *config.EnvironmentConfig, configs *config.Configs, env Environment, kvEngine string) (*Client, error) {
	config := vault.DefaultConfig()
	config.Address = envConfig.URL

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	token, err := envConfig.GetVaultToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get vault token: %w", err)
	}

	client.SetToken(token)

	return &Client{
		Client:         client,
		env:            env,
		kvEngine:       kvEngine,
		redactedKeys:   configs.GetRedactedKeys(),
		redactSecrets:  configs.ShouldRedactSecrets(),
		redactJSONVals: configs.ShouldRedactJSONValues(),
	}, nil
}

func (c *Client) GetSecret(path string) (*vault.KVSecret, error) {
	auth := c.Client.Auth()
	if auth == nil {
		return nil, fmt.Errorf("failed to authenticate with Vault")
	}

	// Check if KV engine exists
	mountOutput, err := c.Sys().ListMounts()
	if err != nil {
		return nil, fmt.Errorf("failed to list vault mounts: %w", err)
	}

	// Ensure the KV engine exists and has a trailing slash
	kvEnginePath := c.kvEngine
	if !strings.HasSuffix(kvEnginePath, "/") {
		kvEnginePath += "/"
	}

	// Check if the engine exists
	if _, exists := mountOutput[kvEnginePath]; !exists {
		return nil, fmt.Errorf("KV engine '%s' does not exist in Vault", c.kvEngine)
	}

	secret, err := c.KVv2(c.kvEngine).Get(context.Background(), path)
	if err != nil {
		// Check if the error is a 404, which means the secret doesn't exist
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("secret not found: %s", path)
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	return secret, nil
}

func (c *Client) CompareSecrets(appName string, targetEnv Environment, pathSuffix string) (*SecretComparison, error) {
	// Validate that pathSuffix is one of the accepted values
	validPaths := []string{"config", "configs", "secret", "secrets"}
	isValidPath := false
	for _, p := range validPaths {
		if p == pathSuffix {
			isValidPath = true
			break
		}
	}
	if !isValidPath {
		return nil, fmt.Errorf("invalid path suffix: %s, must be one of: /config, /configs, /secret, /secrets", pathSuffix)
	}

	currentPath := fmt.Sprintf("%s/%s/%s", appName, c.env, pathSuffix)
	targetPath := fmt.Sprintf("%s/%s/%s", appName, targetEnv, pathSuffix)

	comparison := &SecretComparison{
		Path: currentPath,
	}

	currentSecrets, err := c.GetSecret(currentPath)
	currentExists := true
	if err != nil {
		// Check if the error is because the secret doesn't exist
		if strings.Contains(err.Error(), "secret not found") {
			currentExists = false
		} else {
			return nil, fmt.Errorf("failed to get current secrets: %w", err)
		}
	}

	targetSecrets, err := c.GetSecret(targetPath)
	targetExists := true
	if err != nil {
		// Check if the error is because the secret doesn't exist
		if strings.Contains(err.Error(), "secret not found") {
			targetExists = false
		} else {
			return nil, fmt.Errorf("failed to get target secrets: %w", err)
		}
	}

	// If neither exists, return early with a message
	if !currentExists && !targetExists {
		return nil, fmt.Errorf("secret %s doesn't exist in both environments: %s and %s", pathSuffix, c.env, targetEnv)
	}

	// Handle case where current env doesn't have the secret
	if !currentExists {
		comparison.Path = targetPath
		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "INFO",
			Current:    fmt.Sprintf("Secret doesn't exist in %s environment", c.env),
			Target:     "",
			IsRedacted: false,
			Status:     "-",
		})

		// List all target keys and values
		for key, targetValue := range targetSecrets.Data {
			targetValueStr := fmt.Sprintf("%v", targetValue)
			redacted := c.isRedactedKey(key)
			
			// Check if value is JSON and should be redacted
			redactedJSON, isJSON := c.TryParseAndRedactJSON(targetValueStr)
			if isJSON {
				targetValueStr = redactedJSON
			}
			
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    "", // No current value
				Target:     targetValueStr,
				IsRedacted: redacted,
				Status:     "-",
			})
		}

		return comparison, nil
	}

	// Handle case where target env doesn't have the secret
	if !targetExists {
		comparison.Diffs = append(comparison.Diffs, SecretDiff{
			Key:        "INFO",
			Current:    "",
			Target:     fmt.Sprintf("Secret doesn't exist in %s environment", targetEnv),
			IsRedacted: false,
			Status:     "+",
		})

		// List all current keys and values
		for key, currentValue := range currentSecrets.Data {
			currentValueStr := fmt.Sprintf("%v", currentValue)
			redacted := c.isRedactedKey(key)
			
			// Check if value is JSON and should be redacted
			redactedJSON, isJSON := c.TryParseAndRedactJSON(currentValueStr)
			if isJSON {
				currentValueStr = redactedJSON
			}
			
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    currentValueStr,
				Target:     "", // No target value
				IsRedacted: redacted,
				Status:     "+",
			})
		}

		return comparison, nil
	}

	// Both secrets exist, compare them
	processedKeys := make(map[string]bool)

	for key, currentValue := range currentSecrets.Data {
		processedKeys[key] = true
		targetValue, exists := targetSecrets.Data[key]
		if !exists {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    fmt.Sprintf("%v", currentValue),
				Target:     "",
				IsRedacted: c.isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
				Status:     "+",
			})
			continue
		}

		currentValueStr := fmt.Sprintf("%v", currentValue)
		targetValueStr := fmt.Sprintf("%v", targetValue)

		redacted := c.isRedactedKey(key)
		
		// Check if values are JSON and should be redacted
		redactedCurrentJSON, isCurrentJSON := c.TryParseAndRedactJSON(currentValueStr)
		if isCurrentJSON {
			currentValueStr = redactedCurrentJSON
		}
		
		redactedTargetJSON, isTargetJSON := c.TryParseAndRedactJSON(targetValueStr)
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

	for key, targetValue := range targetSecrets.Data {
		if _, exists := processedKeys[key]; !exists {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    "",
				Target:     fmt.Sprintf("%v", targetValue),
				IsRedacted: c.isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
				Status:     "-",
			})
		}
	}

	return comparison, nil
}

func (c *Client) isRedactedKey(key string) bool {
	if !c.redactSecrets {
		return false
	}
	
	lowerKey := strings.ToLower(key)
	for _, redactedKey := range c.redactedKeys {
		if strings.Contains(lowerKey, strings.ToLower(redactedKey)) {
			return true
		}
	}
	return false
}

// IsJSONValue checks if a string is a valid JSON object or array
func IsJSONValue(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) || (strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"))
}

// RedactJSONValues recursively goes through a JSON object and redacts values with sensitive keys
func (c *Client) RedactJSONValues(data interface{}) interface{} {
	if !c.redactJSONVals {
		return data
	}

	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			if c.isRedactedKey(key) {
				result[key] = "****"
			} else {
				result[key] = c.RedactJSONValues(value)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = c.RedactJSONValues(item)
		}
		return result
	default:
		return v
	}
}

// CompareSecretPaths compares secrets between two full paths
func (c *Client) CompareSecretPaths(sourcePath, targetPath string) (*SecretComparison, error) {
	// Get the current secrets
	currentSecrets, err := c.GetSecret(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get current secrets: %w", err)
	}

	// Get the target secrets
	targetSecrets, err := c.GetSecret(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get target secrets: %w", err)
	}

	// Create a comparison object
	comparison := &SecretComparison{
		Path:  sourcePath,
		Diffs: []SecretDiff{},
	}

	// Track processed keys to avoid duplicates
	processedKeys := make(map[string]bool)

	// Compare current secrets with target secrets
	for key, currentValue := range currentSecrets.Data {
		processedKeys[key] = true

		// Convert value to string for comparison
		currentValueStr := fmt.Sprintf("%v", currentValue)

		// Check if the key exists in target secrets
		targetValue, exists := targetSecrets.Data[key]
		if !exists {
			// Key only exists in current secrets (added)
			// Check if the key should be redacted
			redacted := c.isRedactedKey(key)

			// Try to parse and redact JSON values if needed
			if redacted && c.redactJSONVals {
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
			if redacted && c.redactJSONVals {
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
	for key, targetValue := range targetSecrets.Data {
		if _, exists := processedKeys[key]; !exists {
			// Key only exists in target secrets (removed)
			targetValueStr := fmt.Sprintf("%v", targetValue)

			// Check if the key should be redacted
			redacted := c.isRedactedKey(key)

			// Try to parse and redact JSON values if needed
			if redacted && c.redactJSONVals {
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

// TryParseAndRedactJSON attempts to parse a string as JSON and redact sensitive values
func (c *Client) TryParseAndRedactJSON(value string) (string, bool) {
	if !c.redactJSONVals || !IsJSONValue(value) {
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

// GenerateDiff creates a text diff between two strings
func GenerateDiff(current, target string) string {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(current, target, false)
	return dmp.DiffPrettyText(diffs)
}
