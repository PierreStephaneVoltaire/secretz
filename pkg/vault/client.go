package vault

import (
	"context"
	"fmt"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

type Environment string

const (
	EnvDev  Environment = "dev"
	EnvUAT  Environment = "uat"
	EnvProd Environment = "prod"
)

type Client struct {
	*vault.Client
	env      Environment
	kvEngine string
}

type SecretDiff struct {
	Key        string
	Current    string
	Target     string
	IsRedacted bool
	Status     string // +, -, or * for added, removed, or modified
}
type SecretComparison struct {
	Path  string
	Diffs []SecretDiff
}

func NewClient(addr string, token string, env Environment, kvEngine string) (*Client, error) {
	config := vault.DefaultConfig()
	config.Address = addr

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(token)

	return &Client{
		Client:   client,
		env:      env,
		kvEngine: kvEngine,
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
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    "", // No current value
				Target:     fmt.Sprintf("%v", targetValue),
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
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
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    fmt.Sprintf("%v", currentValue),
				Target:     "", // No target value
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
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
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
				Status:     "+",
			})
			continue
		}

		currentValueStr := fmt.Sprintf("%v", currentValue)
		targetValueStr := fmt.Sprintf("%v", targetValue)

		if currentValueStr != targetValueStr {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    currentValueStr,
				Target:     targetValueStr,
				IsRedacted: isRedactedKey(key) || strings.Contains(pathSuffix, "secret"),
				Status:     "*", // New status for modified values
			})
		}
	}

	for key, targetValue := range targetSecrets.Data {
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

	return comparison, nil
}

func isRedactedKey(key string) bool {
	return strings.HasSuffix(key, "secret") ||
		strings.HasSuffix(key, "secrets") ||
		strings.Contains(key, "password") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "key") ||
		strings.Contains(key, "credential")
}
