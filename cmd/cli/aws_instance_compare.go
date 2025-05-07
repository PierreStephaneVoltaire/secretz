package main

import (
	"fmt"

	"github.com/secretz/vault-promoter/pkg/awssecretsmanager"
	"github.com/spf13/cobra"
)

var (
	awsSourceInstance     string
	awsTargetInstance     string
	awsConfigPathInstance string
	awsEnvInstance        string
	awsTargetPathInstance string
	awsTargetEnvInstance  string
)

var awsInstanceCompareCmd = &cobra.Command{
	Use:   "aws-instance-compare",
	Short: "Compare secrets between AWS Secrets Manager instances",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if required parameters are provided
		if awsConfigPathInstance == "" {
			return fmt.Errorf("--config-path is required")
		}

		if awsEnvInstance == "" {
			return fmt.Errorf("--env is required")
		}

		configs, err := readConfigs()
		if err != nil {
			return err
		}

		// Validate that redact_secrets warning is shown if disabled
		if configs.RedactSecrets != nil && !*configs.RedactSecrets {
			fmt.Println("WARNING: Secret redaction is disabled. Sensitive values may be displayed in plaintext.")
		}

		// Set default target env if not provided
		targetEnv := awsEnvInstance
		if awsTargetEnvInstance != "" {
			targetEnv = awsTargetEnvInstance
		}

		// Set default target path if not provided
		targetPath := awsConfigPathInstance
		if awsTargetPathInstance != "" {
			targetPath = awsTargetPathInstance
		}

		// Perform the comparison
		result, err := awssecretsmanager.CompareAWSSecretInstances(
			awsSourceInstance,
			awsTargetInstance,
			awsConfigPathInstance,
			awsEnvInstance,
			targetPath,
			targetEnv,
			configs,
		)
		if err != nil {
			return fmt.Errorf("failed to compare AWS Secrets Manager instances: %w", err)
		}

		// Print the results
		fmt.Printf("Source Path: %s | Target Path: %s\n", result.SourcePath, result.TargetPath)
		fmt.Printf("Source Instance: %s | Target Instance: %s\n", awsSourceInstance, awsTargetInstance)
		fmt.Printf("Source Env: %s | Target Env: %s\n", result.SourceEnv, result.TargetEnv)
		fmt.Printf("Source Store Type: awssecretsmanager | Target Store Type: awssecretsmanager\n")
		fmt.Println("----------------------------------------")

		if len(result.MissingInSource) > 0 {
			fmt.Printf("\nSecrets missing in source instance (%s):\n", awsSourceInstance)
			for _, path := range result.MissingInSource {
				fmt.Printf("  - %s\n", path)
			}
		}

		if len(result.MissingInTarget) > 0 {
			fmt.Printf("\nSecrets missing in target instance (%s):\n", awsTargetInstance)
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
						fmt.Printf("%sSource (%s): (redacted)\n", statusSymbol, awsSourceInstance)
					} else {
						fmt.Printf("%sSource (%s): %s\n", statusSymbol, awsSourceInstance, diff.Current)
					}
				}

				if diff.Target != "" {
					if diff.IsRedacted {
						fmt.Printf("%sTarget (%s): (redacted)\n", statusSymbol, awsTargetInstance)
					} else {
						fmt.Printf("%sTarget (%s): %s\n", statusSymbol, awsTargetInstance, diff.Target)
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
	awsInstanceCompareCmd.Flags().StringVar(&awsSourceInstance, "source", "dev", "Source AWS Secrets Manager instance (from config file)")
	awsInstanceCompareCmd.Flags().StringVar(&awsTargetInstance, "target", "uat", "Target AWS Secrets Manager instance (from config file)")
	awsInstanceCompareCmd.Flags().StringVar(&awsConfigPathInstance, "config-path", "", "Full path to the source secret (required)")
	awsInstanceCompareCmd.Flags().StringVar(&awsEnvInstance, "env", "", "Source environment name in the config (required)")

	// Optional target-specific flags
	awsInstanceCompareCmd.Flags().StringVar(&awsTargetPathInstance, "target-path", "", "Full path to the target secret (if omitted, uses same as config-path)")
	awsInstanceCompareCmd.Flags().StringVar(&awsTargetEnvInstance, "target-env", "", "Target environment name (if omitted, uses same as env)")

	// Make required flags actually required
	awsInstanceCompareCmd.MarkFlagRequired("config-path")
	awsInstanceCompareCmd.MarkFlagRequired("env")

	// Add the command to the root command
	rootCmd.AddCommand(awsInstanceCompareCmd)
}
