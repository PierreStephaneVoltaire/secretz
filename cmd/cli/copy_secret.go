package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/secretz/vault-promoter/pkg/awssecretsmanager"
	"github.com/secretz/vault-promoter/pkg/comparison"
	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
)

// CopyLogEntry represents a log entry for a copy operation
type CopyLogEntry struct {
	Timestamp   string                 `json:"timestamp"`
	SourceEnv   string                 `json:"source_env"`
	TargetEnv   string                 `json:"target_env"`
	SourcePath  string                 `json:"source_path"`
	TargetPath  string                 `json:"target_path"`
	SourceStore string                 `json:"source_store"`
	TargetStore string                 `json:"target_store"`
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	Keys        map[string]interface{} `json:"keys"`
}

// logCopyOperation logs the copy operation to a file in JSON format
func logCopyOperation(sourceEnv, targetEnv, sourcePath, targetPath string, result *comparison.CopyResult, logFile string) {
	// Create log entry
	entry := CopyLogEntry{
		Timestamp:   time.Now().Format(time.RFC3339),
		SourceEnv:   sourceEnv,
		TargetEnv:   targetEnv,
		SourcePath:  sourcePath,
		TargetPath:  targetPath,
		SourceStore: result.SourceStoreType,
		TargetStore: result.TargetStoreType,
		Success:     result.Success,
		Message:     result.Message,
		Keys:        make(map[string]interface{}),
	}

	// Add keys that were copied (with redacted values for sensitive keys)
	if result.Keys != nil {
		for k, v := range result.Keys {
			// Always redact sensitive values regardless of config
			if isSensitiveKey(k) {
				entry.Keys[k] = "(redacted)"
			} else {
				entry.Keys[k] = v
			}
		}
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Printf("Error creating log entry: %v\n", err)
		return
	}

	// Open log file in append mode or create if it doesn't exist
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer file.Close()

	// Write log entry
	if _, err := file.Write(jsonData); err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
		return
	}

	// Add newline
	if _, err := file.WriteString("\n"); err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
		return
	}

	fmt.Printf("Copy operation logged to %s\n", logFile)
}

// isSensitiveKey checks if a key is sensitive based on common patterns
func isSensitiveKey(key string) bool {
	sensitivePatterns := []string{
		"password", "secret", "token", "key", "credential", "auth", "pwd", "pass",
		"apikey", "api_key", "access_key", "secret_key", "private_key", "cert", "certificate",
	}

	lowerKey := strings.ToLower(key)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerKey, pattern) {
			return true
		}
	}

	return false
}

// promptForConfirmation asks the user for confirmation before proceeding
func promptForConfirmation(message string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", message)

	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

func init() {
	var (
		sourceEnv       string
		sourceKV        string
		targetEnv       string
		targetKV        string
		targetPath      string
		overwrite       bool
		copyConfig      bool
		copySecrets     bool
		onlyCopyKeys    bool
		dryRun          bool
		autoApprove     bool
		logToFile       string
	)

	// copyCmd represents the copy command
	var copyCmd = &cobra.Command{
		Use:   "copy [source-env] [secret-path] [target-env] [target-path]",
		Short: "Copy secrets between environments or stores",
		Long: `Copy secrets between environments or stores.

This command allows you to copy secrets between different environments and store types
(Vault and AWS Secrets Manager). You can specify which keys to copy and whether to
overwrite existing keys in the target.

By default, the command will prompt for confirmation before making any changes.
Use --approve to skip the confirmation prompt, or --dry-run to see what would be copied without making any changes.

All copy operations are logged to the specified log file (--log-to) in JSON format.`,
		Args: cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			// Parse arguments
			sourceEnv = args[0]
			sourcePath := args[1]
			targetEnv = args[2]

			// If target path is not provided, use the same as source
			if len(args) > 3 {
				targetPath = args[3]
			} else {
				targetPath = sourcePath
			}

			// Validate that source and target are not the same
			if sourceEnv == targetEnv && sourcePath == targetPath && sourceKV == targetKV {
				fmt.Println("Error: Cannot copy to the same location. Source and target are identical.")
				os.Exit(1)
			}

			// If dry-run is enabled, show what would be copied without making changes
			if dryRun {
				fmt.Println("DRY RUN MODE: No changes will be made")
				fmt.Printf("Would copy from %s:%s to %s:%s\n", sourceEnv, sourcePath, targetEnv, targetPath)
				fmt.Printf("Source KV: %s, Target KV: %s\n", sourceKV, targetKV)
				fmt.Printf("Options: overwrite=%v, copy-config=%v, copy-secrets=%v, only-copy-keys=%v\n", 
					overwrite, copyConfig, copySecrets, onlyCopyKeys)
				os.Exit(0)
			}

			// Prompt for confirmation unless auto-approve is set
			if !autoApprove {
				message := fmt.Sprintf("Are you sure you want to copy from %s:%s to %s:%s?", 
					sourceEnv, sourcePath, targetEnv, targetPath)
				if !promptForConfirmation(message) {
					fmt.Println("Operation cancelled by user")
					os.Exit(0)
				}
			}

			// Load configuration
			configs, err := config.ReadConfigs(configPath)
			if err != nil {
				fmt.Printf("Error loading config: %v\n", err)
				os.Exit(1)
			}

			// Get source and target configs
			sourceConfig, err := configs.GetEnvironmentConfig(sourceEnv)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			targetConfig, err := configs.GetEnvironmentConfig(targetEnv)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			// Create copy options
			options := comparison.CopyOptions{
				Overwrite:       overwrite,
				CopyConfig:      copyConfig,
				CopySecrets:     copySecrets,
				OnlyCopyKeys:    onlyCopyKeys,
			}

			// Determine the copy operation based on store types
			if sourceConfig.Store == targetConfig.Store {
				// Same store type
				switch sourceConfig.Store {
				case "vault":
					// Source KV must be specified for Vault
					if sourceKV == "" {
						fmt.Println("Error: Source KV engine must be specified when using Vault")
						os.Exit(1)
					}
					
					// Default target KV to source KV if not specified
					if targetKV == "" {
						targetKV = sourceKV
					}

					// Create target Vault client directly
					vaultClient, err := vault.NewClient(targetConfig, configs, vault.Environment(targetEnv), targetKV)
					if err != nil {
						fmt.Printf("Error creating target Vault client: %v\n", err)
						os.Exit(1)
					}

					// Ensure the KV engine exists in target
					err = vaultClient.EnsureKVEngineExists(targetKV)
					if err != nil {
						fmt.Printf("Error ensuring KV engine exists: %v\n", err)
						os.Exit(1)
					}

					// Convert options
					vaultOptions := vault.CopyOptions{
						Overwrite:       options.Overwrite,
						CopyConfig:      options.CopyConfig,
						CopySecrets:     options.CopySecrets,
						OnlyCopyKeys:    options.OnlyCopyKeys,
					}

					// Copy the secret
					err = vaultClient.CopySecret(sourcePath, targetPath, vaultOptions)
					if err != nil {
						fmt.Printf("Error copying secret: %v\n", err)
						os.Exit(1)
					}

					// Create a result for logging
					result := &comparison.CopyResult{
						SourcePath:      sourcePath,
						TargetPath:      targetPath,
						SourceStoreType: "vault",
						TargetStoreType: "vault",
						Success:         true,
						Message:         "Successfully copied secret",
					}

					// Log the copy operation
					logCopyOperation(sourceEnv, targetEnv, sourcePath, targetPath, result, logToFile)

					fmt.Printf("Successfully copied secret from %s/%s to %s/%s\n", sourceEnv, sourcePath, targetEnv, targetPath)

				case "awssecretsmanager":
					// Create AWS clients
					_, err := awssecretsmanager.NewClient(sourceConfig, configs)
					if err != nil {
						fmt.Printf("Error creating source AWS client: %v\n", err)
						os.Exit(1)
					}
					
					awsClient, err := awssecretsmanager.NewClient(targetConfig, configs)
					if err != nil {
						fmt.Printf("Error creating target AWS client: %v\n", err)
						os.Exit(1)
					}

					// Convert options
					awsOptions := awssecretsmanager.CopyOptions{
						Overwrite:       options.Overwrite,
						CopyConfig:      options.CopyConfig,
						CopySecrets:     options.CopySecrets,
						OnlyCopyKeys:    options.OnlyCopyKeys,
					}

					// Copy the secret
					err = awsClient.CopySecret(sourcePath, targetPath, awsOptions, configs)
					if err != nil {
						fmt.Printf("Error copying secret: %v\n", err)
						os.Exit(1)
					}

					// Create a result for logging
					result := &comparison.CopyResult{
						SourcePath:      sourcePath,
						TargetPath:      targetPath,
						SourceStoreType: "awssecretsmanager",
						TargetStoreType: "awssecretsmanager",
						Success:         true,
						Message:         "Successfully copied secret",
					}

					// Log the copy operation
					logCopyOperation(sourceEnv, targetEnv, sourcePath, targetPath, result, logToFile)

					fmt.Printf("Successfully copied secret from %s/%s to %s/%s\n", sourceEnv, sourcePath, targetEnv, targetPath)

				default:
					fmt.Printf("Unsupported store type: %s\n", sourceConfig.Store)
					os.Exit(1)
				}
			} else {
				// Cross-store copy (Vault <-> AWS)
				// Source KV must be specified when source is Vault
				if sourceKV == "" && sourceConfig.Store == "vault" {
					fmt.Println("Error: Source KV engine must be specified when using Vault")
					os.Exit(1)
				}
				
				// Default target KV if not specified and target is Vault
				if targetKV == "" && targetConfig.Store == "vault" {
					targetKV = "secret"
				}

				// Perform cross-store copy
				result, err := comparison.CopyVaultWithAWS(
					sourceEnv, targetEnv, secretPath, targetPath,
					sourceEnv, targetEnv, sourceKV, targetKV,
					configs,
					options,
				)

				if err != nil {
					fmt.Printf("Error copying secret: %v\n", err)
					os.Exit(1)
				}

				if result.Success {
					fmt.Println(result.Message)
				} else {
					fmt.Printf("Failed to copy secret: %s\n", result.Message)
					os.Exit(1)
				}
			}
		},
	}

	// Add flags
	copyCmd.Flags().StringVar(&sourceKV, "source-kv", "", "KV engine name to use in Vault for the source path")
	copyCmd.Flags().StringVar(&targetKV, "target-kv", "", "KV engine name to use in Vault for the target path")
	copyCmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing keys in the target")
	copyCmd.Flags().BoolVar(&copyConfig, "copy-config", false, "Only copy configuration values (non-secret values)")
	copyCmd.Flags().BoolVar(&copySecrets, "copy-secrets", false, "Only copy secret values (keys that match the sensitive_keys list)")
	copyCmd.Flags().BoolVar(&onlyCopyKeys, "only-copy-keys", false, "Only copy the keys, not the values. Values will be empty strings.")
	copyCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be copied without making any changes")
	copyCmd.Flags().BoolVar(&autoApprove, "approve", false, "Automatically approve the copy operation without prompting")
	copyCmd.Flags().StringVar(&logToFile, "log-to", "./vault-promoter-copy.log", "Path to the log file for copy operations")

	// Add to root command
	rootCmd.AddCommand(copyCmd)
}
