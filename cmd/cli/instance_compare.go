package main

import (
	"fmt"

	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
	"github.com/spf13/cobra"
)

var (
	sourceInstance     string
	targetInstance     string
	kvEngineInstance   string
	configPathInstance string
	envInstance        string
	targetPathInstance string
	targetEnvInstance  string
	targetKVInstance   string
)

var instanceCompareCmd = &cobra.Command{
	Use:   "instance-compare",
	Short: "Compare secrets between vault instances",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if required parameters are provided
		if configPathInstance == "" {
			return fmt.Errorf("--config-path is required")
		}

		if envInstance == "" {
			return fmt.Errorf("--env is required")
		}

		if kvEngineInstance == "" {
			return fmt.Errorf("--kv-engine is required")
		}

		configs, err := readConfigs()
		if err != nil {
			return err
		}

		// Validate that redact_secrets warning is shown if disabled
		if configs.RedactSecrets != nil && !*configs.RedactSecrets {
			fmt.Println("WARNING: Secret redaction is disabled. Sensitive values may be displayed in plaintext.")
		}

		// Perform the comparison
		result, err := vault.CompareVaultInstances(
			sourceInstance,
			targetInstance,
			configPathInstance,
			envInstance,
			kvEngineInstance,
			targetPathInstance,
			targetEnvInstance,
			targetKVInstance,
			configs,
		)
		if err != nil {
			return fmt.Errorf("failed to compare vault instances: %w", err)
		}

		// Print the results
		fmt.Printf("Source Path: %s | Target Path: %s\n", result.SourcePath, result.TargetPath)
		fmt.Printf("Source Instance: %s | Target Instance: %s\n", sourceInstance, targetInstance)
		fmt.Printf("Source Env: %s | Target Env: %s\n", result.SourceEnv, result.TargetEnv)
		fmt.Printf("Source KV Engine: %s | Target KV Engine: %s\n", result.SourceKVEngine, result.TargetKVEngine)
		fmt.Println("----------------------------------------")

		if len(result.MissingInSource) > 0 {
			fmt.Printf("\nSecrets missing in source instance (%s):\n", sourceInstance)
			for _, path := range result.MissingInSource {
				fmt.Printf("  - %s\n", path)
			}
		}

		if len(result.MissingInTarget) > 0 {
			fmt.Printf("\nSecrets missing in target instance (%s):\n", targetInstance)
			for _, path := range result.MissingInTarget {
				fmt.Printf("  - %s\n", path)
			}
		}

		if len(result.Comparisons) == 0 {
			fmt.Println("\nNo differences found!")
			return nil
		}

		// Print the comparisons
		for _, comparison := range result.Comparisons {
			fmt.Printf("\nComparison for: %s\n", comparison.Path)
			fmt.Println("----------------------------------------")

			for _, diff := range comparison.Diffs {
				statusPrefix := "  "
				statusSymbol := ""
				if diff.Status == "+" {
					statusPrefix = "+ "
					statusSymbol = "+ "
				} else if diff.Status == "-" {
					statusPrefix = "- "
					statusSymbol = "- "
				} else if diff.Status == "*" {
					statusPrefix = "* "
					statusSymbol = "* "
				}

				// Special handling for INFO key
				if diff.Key == "INFO" {
					if diff.Current != "" {
						fmt.Printf("%s%s\n", statusPrefix, diff.Current)
					}
					if diff.Target != "" {
						fmt.Printf("%s%s\n", statusPrefix, diff.Target)
					}
					continue
				}

				fmt.Printf("%sKey: %s\n", statusPrefix, diff.Key)

				if diff.Current != "" {
					if diff.IsRedacted {
						fmt.Printf("%sSource (%s): (redacted)\n", statusSymbol, sourceInstance)
					} else {
						fmt.Printf("%sSource (%s): %s\n", statusSymbol, sourceInstance, diff.Current)
					}
				}

				if diff.Target != "" {
					if diff.IsRedacted {
						fmt.Printf("%sTarget (%s): (redacted)\n", statusSymbol, targetInstance)
					} else {
						fmt.Printf("%sTarget (%s): %s\n", statusSymbol, targetInstance, diff.Target)
					}
				}

				fmt.Println("---")
			}
		}

		return nil
	},
}

func init() {
	// Initialize the command with flags
	instanceCompareCmd.Flags().StringVar(&sourceInstance, "source", "dev", "Source vault instance (from config file)")
	instanceCompareCmd.Flags().StringVar(&targetInstance, "target", "uat", "Target vault instance (from config file)")
	instanceCompareCmd.Flags().StringVar(&kvEngineInstance, "kv-engine", "", "Source KV engine name (required)")
	instanceCompareCmd.Flags().StringVar(&configPathInstance, "config-path", "", "Full path to the source secret (required)")
	instanceCompareCmd.Flags().StringVar(&envInstance, "env", "", "Source environment name in the config (required)")

	// Optional target-specific flags
	instanceCompareCmd.Flags().StringVar(&targetPathInstance, "target-path", "", "Full path to the target secret (if omitted, uses same as config-path)")
	instanceCompareCmd.Flags().StringVar(&targetEnvInstance, "target-env", "", "Target environment name (if omitted, uses same as env)")
	instanceCompareCmd.Flags().StringVar(&targetKVInstance, "target-kv", "", "Target KV engine name (if omitted, uses same as kv-engine)")

	// Make required flags actually required
	instanceCompareCmd.MarkFlagRequired("config-path")
	instanceCompareCmd.MarkFlagRequired("env")
	instanceCompareCmd.MarkFlagRequired("kv-engine")

	// Add the command to the root command
	rootCmd.AddCommand(instanceCompareCmd)
}

// Utility function to read configs
func readConfigs() (*config.Configs, error) {
	configs, err := config.ReadConfigs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return configs, nil
}
