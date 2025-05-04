package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type VaultConfig struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

type Configs struct {
	Environments map[string]VaultConfig `json:"environments"`
}

func ReadConfigs(configPath string) (*Configs, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file %s does not exist", configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var configs Configs
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if configs.Environments == nil || len(configs.Environments) == 0 {
		return nil, fmt.Errorf("no environments defined in config file")
	}

	return &configs, nil
}

func (c *Configs) GetEnvironmentConfig(env string) (*VaultConfig, error) {
	config, exists := c.Environments[env]
	if !exists {
		return nil, fmt.Errorf("environment %s not found in config", env)
	}

	if config.URL == "" {
		return nil, fmt.Errorf("URL not specified for environment %s", env)
	}

	if config.Token == "" {
		return nil, fmt.Errorf("token not specified for environment %s", env)
	}

	return &config, nil
}
