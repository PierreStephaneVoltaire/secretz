package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/secretz/vault-promoter/pkg/config"
	"github.com/secretz/vault-promoter/pkg/vault"
	"github.com/spf13/cobra"
)

var (
	env        string
	configPath string
	kvEngine   string
	pathSuffix string
	targetEnv  string
	targetKV   string
)

var rootCmd = &cobra.Command{
	Use:   "vault-promoter",
	Short: "Vault secret promotion tool",
	Long:  "A tool for comparing and promoting secrets between Vault environments",
}

var compareCmd = &cobra.Command{
	Use:   "compare [config-path] [target-config-path]",
	Short: "Compare secrets between environments or Vault instances",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sourcePath := args[0]
		targetPath := args[1]

		// If target-env flag is provided, use CompareVaultInstances instead of CompareSecrets
		// This allows comparing across different Vault instances
		useTargetEnv := targetEnv != ""

		configs, err := config.ReadConfigs(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		// If target-env is not provided, use the traditional comparison within the same Vault instance
		if !useTargetEnv {
			currentConfig, err := configs.GetEnvironmentConfig(env)
			if err != nil {
				return fmt.Errorf("failed to get environment config: %w", err)
			}

			client, err := vault.NewClient(currentConfig, configs, vault.Environment(env), kvEngine)
			if err != nil {
				return fmt.Errorf("failed to create vault client: %w", err)
			}

			comparison, err := client.CompareSecretPaths(sourcePath, targetPath)
			if err != nil {
				return fmt.Errorf("failed to compare secrets: %w", err)
			}

			fmt.Printf("Comparing secrets\n")
			fmt.Printf("Source Path: %s | Target Path: %s\n", sourcePath, targetPath)
			fmt.Printf("Source Environment: %s\n", env)
			fmt.Println("----------------------------------------")

			// Print comparison results
			for _, diff := range comparison.Diffs {
				statusPrefix := "  "
				if diff.Status == "+" {
					statusPrefix = "+ "
				} else if diff.Status == "-" {
					statusPrefix = "- "
				}

				fmt.Printf("%sKey: %s\n", statusPrefix, diff.Key)

				if diff.Current != "" {
					if diff.IsRedacted {
						fmt.Printf("%sCurrent (%s): (redacted)\n", statusPrefix, env)
					} else {
						fmt.Printf("%sCurrent (%s): %s\n", statusPrefix, env, diff.Current)
					}
				}

				if diff.Target != "" {
					if diff.IsRedacted {
						fmt.Printf("%sTarget (%s): (redacted)\n", statusPrefix, targetPath)
					} else {
						fmt.Printf("%sTarget (%s): %s\n", statusPrefix, targetPath, diff.Target)
					}
				}

				fmt.Println("---")
			}
			return nil
		}

		// Use CompareVaultInstances for cross-instance comparison
		// If targetKV is not specified, use the same KV engine
		targetKVToUse := kvEngine
		if targetKV != "" {
			targetKVToUse = targetKV
		}

		// Use the source instance name as the current environment
		// and the target instance name as the target environment
		result, err := vault.CompareVaultInstances(
			env,           // sourceInstanceName
			targetEnv,     // targetInstanceName
			sourcePath,    // configPath (full path to source secret)
			env,           // sourceEnv
			kvEngine,      // kvEngine
			targetPath,    // targetConfigPath (full path to target secret)
			targetEnv,     // targetEnv
			targetKVToUse, // targetKVEngine
			configs,
		)
		if err != nil {
			return fmt.Errorf("failed to compare vault instances: %w", err)
		}

		// Print the results
		fmt.Printf("Source Path: %s | Target Path: %s\n", result.SourcePath, result.TargetPath)
		fmt.Printf("Source Instance: %s | Target Instance: %s\n", env, targetEnv)
		fmt.Printf("Source Env: %s | Target Env: %s\n", result.SourceEnv, result.TargetEnv)
		fmt.Printf("Source KV Engine: %s | Target KV Engine: %s\n", result.SourceKVEngine, result.TargetKVEngine)
		fmt.Println("----------------------------------------")

		// Print missing secrets
		if len(result.MissingInSource) > 0 {
			fmt.Printf("\nSecrets missing in source instance (%s):\n", env)
			for _, path := range result.MissingInSource {
				fmt.Printf("  - %s\n", path)
			}
		}

		if len(result.MissingInTarget) > 0 {
			fmt.Printf("\nSecrets missing in target instance (%s):\n", targetEnv)
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
						fmt.Printf("%s\n", diff.Current)
					}
					if diff.Target != "" {
						fmt.Printf("%s\n", diff.Target)
					}
					continue
				}

				fmt.Printf("%sKey: %s\n", statusPrefix, diff.Key)

				if diff.Current != "" {
					if diff.IsRedacted {
						fmt.Printf("%sSource (%s): (redacted)\n", statusSymbol, env)
					} else {
						fmt.Printf("%sSource (%s): %s\n", statusSymbol, env, diff.Current)
					}
				}

				if diff.Target != "" {
					if diff.IsRedacted {
						fmt.Printf("%sTarget (%s): (redacted)\n", statusSymbol, targetEnv)
					} else {
						fmt.Printf("%sTarget (%s): %s\n", statusSymbol, targetEnv, diff.Target)
					}
				}

				fmt.Println("---")
			}
		}

		return nil

	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "./.vaultconfigs", "Path to the vault configuration file")
	rootCmd.PersistentFlags().StringVar(&env, "env", "dev", "Current environment (dev/uat/prod)")
	rootCmd.PersistentFlags().StringVar(&kvEngine, "kv-engine", "kv", "KV engine to use in Vault")
	rootCmd.PersistentFlags().StringVar(&pathSuffix, "config-path", "config", "Path suffix to use (config, configs, secret, secrets)")
	compareCmd.Flags().StringVar(&targetEnv, "target-env", "", "Target environment (if different from source env)")
	compareCmd.Flags().StringVar(&targetKV, "target-kv", "", "Target KV engine (if different from source KV engine)")

	cobra.OnInitialize(func() {
		if !filepath.IsAbs(configPath) {
			cwd, _ := os.Getwd()
			configPath = filepath.Join(cwd, configPath)
		}
	})

	rootCmd.AddCommand(compareCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
