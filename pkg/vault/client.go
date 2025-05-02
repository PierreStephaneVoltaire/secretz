package vault

import (
	"context"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"strings"
)

type Environment string

const (
	EnvDev  Environment = "dev"
	EnvUAT  Environment = "uat"
	EnvProd Environment = "prod"
)

type Client struct {
	*vault.Client
	env Environment
}

type SecretDiff struct {
	Key        string
	Current    string
	Target     string
	IsRedacted bool
}
type SecretComparison struct {
	Path  string
	Diffs []SecretDiff
}

func NewClient(addr string, token string, env Environment) (*Client, error) {
	config := vault.DefaultConfig()
	config.Address = addr

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	client.SetToken(token)

	return &Client{
		Client: client,
		env:    env,
	}, nil
}

func (c *Client) GetSecret(path string) (*vault.KVSecret, error) {
	print(path)
	auth := c.Client.Auth()
	if auth == nil {
		return nil, fmt.Errorf("failed to authenticate with Vault")
	}

	secret, err := c.KVv2("kv").Get(context.Background(), path)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}
	return secret, nil
}

func (c *Client) CompareSecrets(appName string, targetEnv Environment) (*SecretComparison, error) {
	currentPath := fmt.Sprintf("%s/%s/config", appName, c.env)
	targetPath := fmt.Sprintf("%s/%s/config", appName, targetEnv)

	currentSecrets, err := c.GetSecret(currentPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get current secrets: %w", err)
	}

	targetSecrets, err := c.GetSecret(targetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get target secrets: %w", err)
	}

	comparison := &SecretComparison{
		Path: currentPath,
	}
	for key, currentValue := range currentSecrets.Data {
		targetValue, exists := targetSecrets.Data[key]
		if !exists {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    fmt.Sprintf("%v", currentValue),
				Target:     "",
				IsRedacted: strings.HasSuffix(key, "secrets")})
			continue
		}
		if fmt.Sprintf("%v", currentValue) != fmt.Sprintf("%v", targetValue) {
			comparison.Diffs = append(comparison.Diffs, SecretDiff{
				Key:        key,
				Current:    fmt.Sprintf("%v", currentValue),
				Target:     fmt.Sprintf("%v", targetValue),
				IsRedacted: strings.HasSuffix(key, "secrets")})
		}
	}

	return comparison, nil
}
