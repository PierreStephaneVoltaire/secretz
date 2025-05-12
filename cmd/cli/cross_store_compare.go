package main

import (
	"fmt"

	"github.com/secretz/vault-promoter/pkg/comparison"
	"github.com/spf13/cobra"
)

var (
	crossSourceInstance     string
	crossTargetInstance     string
	crossKVEngineInstance   string
	crossConfigPathInstance string
	crossEnvInstance        string
	crossTargetPathInstance string
	crossTargetEnvInstance  string
)

var crossStoreCompareCmd = &cobra.Command{
	Use:   "cross-store-compare",
	Short: "Compare secrets between Vault and AWS Secrets Manager",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if required parameters are provided
		if crossConfigPathInstance == "" {
			return fmt.Errorf("--config-path is required")
		}

		if crossEnvInstance == "" {
			return fmt.Errorf("--env is required")
		}

		// Only required for Vault sources
		requireKVEngine := false

		configs, err := readConfigs()
		if err != nil {
			return err
		}

		// Check that one source is Vault and the other is AWS Secrets Manager
		sourceConfig, err := configs.GetEnvironmentConfig(crossSourceInstance)
		if err != nil {
			return fmt.Errorf("failed to get source config: %w", err)
		}

		targetConfig, err := configs.GetEnvironmentConfig(crossTargetInstance)
		if err != nil {
			return fmt.Errorf("failed to get target config: %w", err)
		}

		isValidCrossStoreComparison :=
			(sourceConfig.Store == "vault" && targetConfig.Store == "awssecretsmanager") ||
				(sourceConfig.Store == "awssecretsmanager" && targetConfig.Store == "vault")

		if !isValidCrossStoreComparison {
			return fmt.Errorf("cross-store-compare requires one source to be vault and one to be awssecretsmanager")
		}

		// Validate that KV engine is specified if source is Vault
		if sourceConfig.Store == "vault" && crossKVEngineInstance == "" {
			requireKVEngine = true
		}

		if requireKVEngine {
			return fmt.Errorf("--kv-engine is required when source is a Vault instance")
		}

		// Validate that redact_secrets warning is shown if disabled
		if configs.RedactSecrets != nil && !*configs.RedactSecrets {
			fmt.Println("WARNING: Secret redaction is disabled. Sensitive values may be displayed in plaintext.")
		}

		// Set target path and env if not provided
		targetPath := crossConfigPathInstance
		if crossTargetPathInstance != "" {
			targetPath = crossTargetPathInstance
		}

		targetEnv := crossEnvInstance
		if crossTargetEnvInstance != "" {
			targetEnv = crossTargetEnvInstance
		}

		// Perform the comparison
		result, err := comparison.CompareVaultWithAWS(
			crossSourceInstance,
			crossTargetInstance,
			crossConfigPathInstance,
			targetPath,
			crossEnvInstance,
			targetEnv,
			crossKVEngineInstance,
			configs,
		)
		if err != nil {
			return fmt.Errorf("failed to compare stores: %w", err)
		}

		// Print the results
		fmt.Printf("Source Path: %s | Target Path: %s\n", result.SourcePath, result.TargetPath)
		fmt.Printf("Source Instance: %s | Target Instance: %s\n", crossSourceInstance, crossTargetInstance)
		fmt.Printf("Source Env: %s | Target Env: %s\n", result.SourceEnv, result.TargetEnv)
		fmt.Printf("Source Store Type: %s | Target Store Type: %s\n", result.SourceStoreType, result.TargetStoreType)
		fmt.Println("----------------------------------------")

		if len(result.MissingInSource) > 0 {
			fmt.Printf("\nSecrets missing in source instance (%s):\n", crossSourceInstance)
			for _, path := range result.MissingInSource {
				fmt.Printf("  - %s\n", path)
			}
		}

		if len(result.MissingInTarget) > 0 {
			fmt.Printf("\nSecrets missing in target instance (%s):\n", crossTargetInstance)
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

				// Special handling for INFO and ERROR keys
				if diff.Key == "INFO" || diff.Key == "ERROR" {
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
						fmt.Printf("%sSource (%s): (redacted)\n", statusSymbol, crossSourceInstance)
					} else {
						fmt.Printf("%sSource (%s): %s\n", statusSymbol, crossSourceInstance, diff.Current)
					}
				}

				if diff.Target != "" {
					if diff.IsRedacted {
						fmt.Printf("%sTarget (%s): (redacted)\n", statusSymbol, crossTargetInstance)
					} else {
						fmt.Printf("%sTarget (%s): %s\n", statusSymbol, crossTargetInstance, diff.Target)
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
	crossStoreCompareCmd.Flags().StringVar(&crossSourceInstance, "source", "dev", "Source instance (from config file)")
	crossStoreCompareCmd.Flags().StringVar(&crossTargetInstance, "target", "staging", "Target instance (from config file)")
	crossStoreCompareCmd.Flags().StringVar(&crossKVEngineInstance, "kv-engine", "", "KV engine name (required for Vault sources)")
	crossStoreCompareCmd.Flags().StringVar(&crossConfigPathInstance, "config-path", "", "Full path to the source secret (required)")
	crossStoreCompareCmd.Flags().StringVar(&crossEnvInstance, "env", "", "Source environment name in the config (required)")

	// Optional target-specific flags
	crossStoreCompareCmd.Flags().StringVar(&crossTargetPathInstance, "target-path", "", "Full path to the target secret (if omitted, uses same as config-path)")
	crossStoreCompareCmd.Flags().StringVar(&crossTargetEnvInstance, "target-env", "", "Target environment name (if omitted, uses same as env)")

	// Make required flags actually required
	crossStoreCompareCmd.MarkFlagRequired("config-path")
	crossStoreCompareCmd.MarkFlagRequired("env")

	// Add the command to the root command
	rootCmd.AddCommand(crossStoreCompareCmd)
}
