package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/secretz/vault-promoter/pkg/awssecretsmanager"
	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
)

// SplitLogEntry represents a log entry for a split operation
type SplitLogEntry struct {
	Timestamp   string   `json:"timestamp"`
	SourceEnv   string   `json:"source_env"`
	SourcePath  string   `json:"source_path"`
	TargetPath  string   `json:"target_path"`
	SourceStore string   `json:"source_store"`
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	SplitKeys   []string `json:"split_keys"` // List of keys that were split
}

// getKeysFromMap extracts keys from a map and returns them as a slice of strings
func getKeysFromMap(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// logSplitOperation logs the split operation to a file in JSON format
func logSplitOperation(sourceEnv, sourcePath, targetPath string, sourceStore string, success bool, message string, splitKeys []string, logFile string) {
	// Create log entry
	entry := SplitLogEntry{
		Timestamp:   time.Now().Format(time.RFC3339),
		SourceEnv:   sourceEnv,
		SourcePath:  sourcePath,
		TargetPath:  targetPath,
		SourceStore: sourceStore,
		Success:     success,
		Message:     message,
		SplitKeys:   splitKeys,
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

	fmt.Printf("Split operation logged to %s\n", logFile)
}

func init() {
	var (
		sourceEnv   string
		targetEnv   string
		targetPath  string
		sourceKV    string
		targetKV    string
		dryRun      bool
		autoApprove bool
		logToFile   string
	)

	// splitCmd represents the split command
	var splitCmd = &cobra.Command{
		Use:   "split [source-env] [source-path] [target-path]",
		Short: "Split sensitive keys from source to target path",
		Long: `Split sensitive keys from source to target path.

This command extracts sensitive keys (as defined in sensitive_keys in the config) 
from the source path and moves them to the target path. The sensitive keys are 
removed from the source after they are successfully copied to the target.

By default, the command will prompt for confirmation before making any changes.
Use --approve to skip the confirmation prompt, or --dry-run to see what would be split without making any changes.

This command only works with JSON-formatted secrets and will not work with string values.

All split operations are logged to the specified log file (--log-to) in JSON format.`,
		Args: cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			// Parse arguments
			sourceEnv = args[0]
			sourcePath := args[1]
			targetPath = args[2]

			if targetEnv == "" {
				targetEnv = sourceEnv
			}
			if dryRun {
				fmt.Println("DRY RUN MODE: No changes will be made")
				fmt.Printf("Would split sensitive keys from %s:%s to %s\n", sourceEnv, sourcePath, targetPath)
				fmt.Printf("Source KV: %s, Target KV: %s\n", sourceKV, targetKV)
				os.Exit(0)
			}

			// Prompt for confirmation unless auto-approve is set
			if !autoApprove {
				message := fmt.Sprintf("Are you sure you want to split sensitive keys from %s:%s to %s?",
					sourceEnv, sourcePath, targetPath)
				if !promptForConfirmation(message) {
					fmt.Println("Operation cancelled by user")
					os.Exit(0)
				}
			}

			configs, err := config.ReadConfigs(configPath)
			if err != nil {
				fmt.Printf("Error loading config: %v\n", err)
				os.Exit(1)
			}

			sourceConfig, err := configs.GetEnvironmentConfig(sourceEnv)
			if err != nil {
				fmt.Printf("Error getting source environment config: %v\n", err)
				os.Exit(1)
			}

			storeType := sourceConfig.Store
			fmt.Printf("Source store type: %s\n", storeType)

			// Get target environment config
			targetConfig, err := configs.GetEnvironmentConfig(targetEnv)
			if err != nil {
				fmt.Printf("Error getting target environment config: %v\n", err)
				os.Exit(1)
			}

			// Check if source and target store types match
			targetStoreType := targetConfig.Store
			fmt.Printf("Target store type: %s\n", targetStoreType)

			// Handle Vault-specific configuration if source is Vault
			if storeType == "vault" {
				// Source KV must be specified for Vault
				if sourceKV == "" {
					fmt.Println("Error: Source KV engine must be specified when using Vault")
					os.Exit(1)
				}

				// Default target KV to source KV if not specified
				if targetKV == "" {
					targetKV = sourceKV
				}

				// Create Vault client
				vaultClient, err := vault.NewClient(sourceConfig, configs, vault.Environment(sourceEnv), sourceKV)
				if err != nil {
					fmt.Printf("Error creating Vault client: %v\n", err)
					os.Exit(1)
				}

				// Ensure the target KV engine exists
				err = vaultClient.EnsureKVEngineExists(targetKV)
				if err != nil {
					fmt.Printf("Error ensuring KV engine exists: %v\n", err)
					os.Exit(1)
				}
			}

			// Process based on store type
			var sourceSecret map[string]interface{}
			var isJSON bool
			var sourceClient interface{}
			var targetClient interface{}

			// First, get the source secret and check if target exists
			if storeType == "vault" {
				// Get source Vault client
				vaultSourceClient, err := vault.NewClient(sourceConfig, configs, vault.Environment(sourceEnv), sourceKV)
				if err != nil {
					fmt.Printf("Error creating source Vault client: %v\n", err)
					os.Exit(1)
				}
				sourceClient = vaultSourceClient

				// Get source secret from Vault
				secret, err := vaultSourceClient.GetSecret(sourcePath)
				if err != nil {
					fmt.Printf("Error getting source secret: %v\n", err)
					os.Exit(1)
				}

				// Convert the KVSecret to a map
				sourceSecret = secret.Data
				isJSON = true // Vault secrets are always structured as JSON

				// Get target Vault client (may be the same as source)
				vaultTargetClient, err := vault.NewClient(targetConfig, configs, vault.Environment(targetEnv), targetKV)
				if err != nil {
					fmt.Printf("Error creating target Vault client: %v\n", err)
					os.Exit(1)
				}
				targetClient = vaultTargetClient

				// Check if target already exists
				_, err = vaultTargetClient.GetSecret(targetPath)
				if err == nil {
					fmt.Printf("Error: Target path %s already exists. Split operation requires a new target path.\n", targetPath)
					os.Exit(1)
				} else if !strings.Contains(err.Error(), "not found") {
					// If the error is not a 'not found' error, it's a different error
					fmt.Printf("Error checking target path: %v\n", err)
					os.Exit(1)
				}
			} else if storeType == "awssecretsmanager" {
				// Get source AWS Secrets Manager client
				awsSourceClient, err := awssecretsmanager.NewClient(sourceConfig, configs)
				if err != nil {
					fmt.Printf("Error creating source AWS Secrets Manager client: %v\n", err)
					os.Exit(1)
				}
				sourceClient = awsSourceClient

				// Get source secret from AWS Secrets Manager
				sourceSecret, isJSON, err = awsSourceClient.GetSecret(sourcePath)
				if err != nil {
					fmt.Printf("Error getting source secret: %v\n", err)
					os.Exit(1)
				}

				// Check if this is a non-JSON secret
				if !isJSON {
					fmt.Println("Error: Source secret is not in JSON format. Split operation only works with JSON-formatted secrets.")
					os.Exit(1)
				}

				// Get target AWS Secrets Manager client (may be the same as source)
				awsTargetClient, err := awssecretsmanager.NewClient(targetConfig, configs)
				if err != nil {
					fmt.Printf("Error creating target AWS Secrets Manager client: %v\n", err)
					os.Exit(1)
				}
				targetClient = awsTargetClient

				// Check if target already exists
				_, _, err = awsTargetClient.GetSecret(targetPath)
				if err == nil {
					fmt.Printf("Error: Target path %s already exists. Split operation requires a new target path.\n", targetPath)
					os.Exit(1)
				} else if !strings.Contains(err.Error(), "not found") {
					// If the error is not a 'not found' error, it's a different error
					fmt.Printf("Error checking target path: %v\n", err)
					os.Exit(1)
				}
			} else {
				fmt.Printf("Error: Unsupported store type: %s. Only 'vault' and 'awssecretsmanager' are supported.\n", storeType)
				os.Exit(1)
			}

			// Validate source secret
			if len(sourceSecret) == 0 {
				fmt.Println("Error: Source secret is empty")
				os.Exit(1)
			}

			sensitiveKeys := configs.GetSensitiveKeys()
			if len(sensitiveKeys) == 0 {
				fmt.Println("Error: No sensitive keys defined in configuration. Nothing to split.")
				os.Exit(1)
			}

			fmt.Printf("Found %d sensitive key patterns defined in config: %s\n",
				len(sensitiveKeys), strings.Join(sensitiveKeys, ", "))

			sensitiveData := make(map[string]interface{})
			newSourceData := make(map[string]interface{})
			splitKeysList := []string{}

			if len(sensitiveKeys) == 0 {
				fmt.Println("Error: No sensitive keys defined in configuration. Nothing to split.")
				os.Exit(1)
			}

			foundSensitiveKeys := false
			for k, v := range sourceSecret {
				isSensitive := false
				for _, sensitiveKey := range sensitiveKeys {
					if strings.EqualFold(k, sensitiveKey) ||
						strings.Contains(strings.ToLower(k), strings.ToLower(sensitiveKey)) {
						isSensitive = true
						foundSensitiveKeys = true
						break
					}
				}

				if isSensitive {
					sensitiveData[k] = v
					splitKeysList = append(splitKeysList, k)
				} else {
					newSourceData[k] = v
				}
			}

			if !foundSensitiveKeys {
				fmt.Printf("Error: No keys in the source secret match any of the sensitive key patterns defined in the config.\n")
				fmt.Printf("Source secret keys: %v\n", getKeysFromMap(sourceSecret))
				fmt.Printf("Sensitive key patterns: %v\n", sensitiveKeys)
				os.Exit(1)
			}

			fmt.Printf("Found %d sensitive keys to split: %s\n", len(sensitiveData), strings.Join(splitKeysList, ", "))

			// Create target with sensitive keys and update source with non-sensitive keys
			if storeType == "vault" {
				vaultSourceClient := sourceClient.(*vault.Client)
				vaultTargetClient := targetClient.(*vault.Client)

				// Create target with sensitive keys
				err = vaultTargetClient.WriteSecret(targetPath, sensitiveData)
				if err != nil {
					fmt.Printf("Error writing target secret: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("Successfully created target secret at %s with sensitive keys\n", targetPath)

				// Update source with non-sensitive keys
				err = vaultSourceClient.WriteSecret(sourcePath, newSourceData)
				if err != nil {
					fmt.Printf("Error updating source secret: %v\n", err)
					fmt.Println("WARNING: Sensitive keys have been copied to the target but source was not updated!")
					os.Exit(1)
				}
			} else if storeType == "awssecretsmanager" {
				// Use the AWS Secrets Manager clients we already created
				awsSourceClient := sourceClient.(*awssecretsmanager.Client)
				awsTargetClient := targetClient.(*awssecretsmanager.Client)

				// For AWS Secrets Manager, we need to:
				// 1. Create a new secret at targetPath with sensitive data
				// 2. Update the source secret with only non-sensitive data
				_, _, err = awsTargetClient.GetSecret(targetPath)
				if err == nil {
					fmt.Printf("Error: Target path %s already exists. Split operation requires a new target path.\n", targetPath)
					os.Exit(1)
				} else if !strings.Contains(err.Error(), "not found") {
					fmt.Printf("Error checking target path: %v\n", err)
					os.Exit(1)
				}

				// Create the target secret with sensitive data directly
				targetOptions := awssecretsmanager.CopyOptions{
					Overwrite: true,
				}

				// Create the target secret with sensitive data
				err = awsTargetClient.CopySecretData(sensitiveData, targetPath, targetOptions, configs)
				if err != nil {
					fmt.Printf("Error creating target secret: %v\n", err)
					os.Exit(1)
				}

				fmt.Printf("Successfully created target secret at %s with sensitive keys\n", targetPath)

				// Update the source secret with only the non-sensitive data
				sourceOptions := awssecretsmanager.CopyOptions{
					Overwrite: true,
					Prune:     true, // Ensure sensitive keys are removed
				}

				err = awsSourceClient.CopySecretData(newSourceData, sourcePath, sourceOptions, configs)
				if err != nil {
					fmt.Printf("Error updating source secret: %v\n", err)
					fmt.Println("WARNING: Sensitive keys have been copied to the target but source was not updated!")
					os.Exit(1)
				}
			}

			logSplitOperation(sourceEnv, sourcePath, targetPath, storeType, true,
				"Successfully split sensitive keys", splitKeysList, logToFile)

			fmt.Printf("Successfully split %d sensitive keys from %s to %s\n",
				len(sensitiveData), sourcePath, targetPath)
		},
	}

	splitCmd.Flags().StringVar(&sourceKV, "source-kv", "", "KV engine name to use in Vault for the source path")
	splitCmd.Flags().StringVar(&targetKV, "target-kv", "", "KV engine name to use in Vault for the target path")
	splitCmd.Flags().StringVar(&targetEnv, "target-env", "", "Target environment (defaults to source environment if not specified)")
	splitCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be split without making any changes")
	splitCmd.Flags().BoolVar(&autoApprove, "approve", false, "Automatically approve the split operation without prompting")
	splitCmd.Flags().StringVar(&logToFile, "log-to", "./vault-promoter-split.log", "Path to the log file for split operations")
	rootCmd.AddCommand(splitCmd)
}
