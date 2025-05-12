package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
)

// SplitLogEntry represents a log entry for a split operation
type SplitLogEntry struct {
	Timestamp   string                 `json:"timestamp"`
	SourceEnv   string                 `json:"source_env"`
	SourcePath  string                 `json:"source_path"`
	TargetPath  string                 `json:"target_path"`
	SourceStore string                 `json:"source_store"`
	Success     bool                   `json:"success"`
	Message     string                 `json:"message"`
	SplitKeys   []string               `json:"split_keys"` // List of keys that were split
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

			// If target environment is not specified, use source environment
			if targetEnv == "" {
				targetEnv = sourceEnv
			}

			// If dry-run is enabled, show what would be split without making changes
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

			// Load configuration
			configs, err := config.ReadConfigs(configPath)
			if err != nil {
				fmt.Printf("Error loading config: %v\n", err)
				os.Exit(1)
			}

			// Get source config
			sourceConfig, err := configs.GetEnvironmentConfig(sourceEnv)
			if err != nil {
				fmt.Printf("Error getting source environment config: %v\n", err)
				os.Exit(1)
			}

			// Get target config (may be the same as source if target-env not specified)
			targetConfig, err := configs.GetEnvironmentConfig(targetEnv)
			if err != nil {
				fmt.Printf("Error getting target environment config: %v\n", err)
				os.Exit(1)
			}

			// Currently only support Vault for split operation
			if sourceConfig.Store != "vault" || targetConfig.Store != "vault" {
				fmt.Println("Error: Split operation is currently only supported for Vault")
				os.Exit(1)
			}

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

			// Get source secret
			secret, err := vaultClient.GetSecret(sourcePath)
			if err != nil {
				fmt.Printf("Error getting source secret: %v\n", err)
				os.Exit(1)
			}

			// Convert the KVSecret to a map
			sourceSecret := secret.Data
			if sourceSecret == nil {
				fmt.Println("Error: Source secret is empty or not in JSON format")
				os.Exit(1)
			}

			// Check if target already exists
			_, err = vaultClient.GetSecret(targetPath)
			if err == nil {
				fmt.Printf("Error: Target path %s already exists. Split operation requires a new target path.\n", targetPath)
				os.Exit(1)
			} else if !strings.Contains(err.Error(), "not found") {
				// If the error is not a 'not found' error, it's a different error
				fmt.Printf("Error checking target path: %v\n", err)
				os.Exit(1)
			}

			// Extract sensitive keys
			sensitiveKeys := configs.GetSensitiveKeys()
			if len(sensitiveKeys) == 0 {
				fmt.Println("Error: No sensitive keys defined in configuration. Nothing to split.")
				os.Exit(1)
			}

			// Validate that there are sensitive keys defined in the config
			fmt.Printf("Found %d sensitive key patterns defined in config: %s\n", 
				len(sensitiveKeys), strings.Join(sensitiveKeys, ", "))

			// Create maps for sensitive and non-sensitive keys
			sensitiveData := make(map[string]interface{})
			newSourceData := make(map[string]interface{})
			splitKeysList := []string{}

			// Check if there are any sensitive keys in the source
			foundSensitiveKeys := false
			for k, v := range sourceSecret {
				isSensitive := false
				for _, sensitiveKey := range sensitiveKeys {
					if strings.ToLower(k) == strings.ToLower(sensitiveKey) || 
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

			// Show what would be split
			fmt.Printf("Found %d sensitive keys to split: %s\n", len(sensitiveData), strings.Join(splitKeysList, ", "))

			// Create target with sensitive keys
			err = vaultClient.WriteSecret(targetPath, sensitiveData)
			if err != nil {
				fmt.Printf("Error writing target secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Successfully created target secret at %s with sensitive keys\n", targetPath)

			// Update source with non-sensitive keys
			err = vaultClient.WriteSecret(sourcePath, newSourceData)
			if err != nil {
				fmt.Printf("Error updating source secret: %v\n", err)
				fmt.Println("WARNING: Sensitive keys have been copied to the target but source was not updated!")
				os.Exit(1)
			}

			// Log the split operation
			logSplitOperation(sourceEnv, sourcePath, targetPath, "vault", true, 
				"Successfully split sensitive keys", splitKeysList, logToFile)

			fmt.Printf("Successfully split %d sensitive keys from %s to %s\n", 
				len(sensitiveData), sourcePath, targetPath)
		},
	}

	// Add flags
	splitCmd.Flags().StringVar(&sourceKV, "source-kv", "", "KV engine name to use in Vault for the source path")
	splitCmd.Flags().StringVar(&targetKV, "target-kv", "", "KV engine name to use in Vault for the target path")
	splitCmd.Flags().StringVar(&targetEnv, "target-env", "", "Target environment (defaults to source environment if not specified)")
	splitCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be split without making any changes")
	splitCmd.Flags().BoolVar(&autoApprove, "approve", false, "Automatically approve the split operation without prompting")
	splitCmd.Flags().StringVar(&logToFile, "log-to", "./vault-promoter-split.log", "Path to the log file for split operations")

	// Add to root command
	rootCmd.AddCommand(splitCmd)
}
