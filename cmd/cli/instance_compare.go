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
	pathSuffixInstance string
	envInstance        string
)

var instanceCompareCmd = &cobra.Command{
	Use:   "instance-compare [app-name]",
	Short: "Compare secrets between vault instances",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		appName := args[0]

		configs, err := readConfigs()
		if err != nil {
			return err
		}

		// Perform the comparison
		result, err := vault.CompareVaultInstances(
			sourceInstance,
			targetInstance,
			appName,
			envInstance,
			kvEngineInstance,
			pathSuffixInstance,
			configs,
		)
		if err != nil {
			return fmt.Errorf("failed to compare vault instances: %w", err)
		}

		// Print the results
		fmt.Printf("Comparing secrets for %s\n", appName)
		fmt.Printf("Source Instance: %s | Target Instance: %s\n", sourceInstance, targetInstance)
		fmt.Printf("Environment: %s | KV Engine: %s | Path Suffix: %s\n",
			envInstance, kvEngineInstance, pathSuffixInstance)
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
	instanceCompareCmd.Flags().StringVar(&kvEngineInstance, "kv-engine", "kv", "KV engine to use in both vault instances")
	instanceCompareCmd.Flags().StringVar(&pathSuffixInstance, "config-path", "config", "Path suffix to use (config, configs, secret, secrets)")
	instanceCompareCmd.Flags().StringVar(&envInstance, "env", "dev", "Environment to compare within both instances (dev/uat/prod)")

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
