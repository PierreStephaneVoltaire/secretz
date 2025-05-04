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
)

var rootCmd = &cobra.Command{
	Use:   "vault-promoter",
	Short: "Vault secret promotion tool",
	Long:  "A tool for comparing and promoting secrets between Vault environments",
}

var compareCmd = &cobra.Command{
	Use:   "compare [app-name] [target-env]",
	Short: "Compare secrets between environments",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		appName := args[0]
		targetEnv := vault.Environment(args[1])

		configs, err := config.ReadConfigs(configPath)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}

		currentConfig, err := configs.GetEnvironmentConfig(env)
		if err != nil {
			return fmt.Errorf("failed to get environment config: %w", err)
		}

		client, err := vault.NewClient(currentConfig.URL, currentConfig.Token, vault.Environment(env))
		if err != nil {
			return fmt.Errorf("failed to create vault client: %w", err)
		}

		comparison, err := client.CompareSecrets(appName, targetEnv)
		if err != nil {
			return fmt.Errorf("failed to compare secrets: %w", err)
		}

		fmt.Printf("Comparing secrets for %s\n", comparison.Path)
		fmt.Printf("Current Environment: %s | Target Environment: %s\n", env, string(targetEnv))
		fmt.Println("----------------------------------------")

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
					fmt.Printf("%sTarget (%s): (redacted)\n", statusPrefix, targetEnv)
				} else {
					fmt.Printf("%sTarget (%s): %s\n", statusPrefix, targetEnv, diff.Target)
				}
			}

			fmt.Println("---")
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "./.vaultconfigs", "Path to the vault configuration file")
	rootCmd.PersistentFlags().StringVar(&env, "env", "dev", "Current environment (dev/uat/prod)")

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
