package main

import (
	"fmt"
	"github.com/secretz/vault-promoter/pkg/vault"
	"github.com/spf13/cobra"
	"os"
)

var (
	vaultAddr  string
	vaultToken string
	env        string
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

		client, err := vault.NewClient(vaultAddr, vaultToken, vault.Environment(env))
		if err != nil {
			return fmt.Errorf("failed to create vault client: %w", err)
		}

		comparison, err := client.CompareSecrets(appName, targetEnv)
		if err != nil {
			return fmt.Errorf("failed to compare secrets: %w", err)
		}

		fmt.Printf("Comparing secrets for %s\n", comparison.Path)
		for _, diff := range comparison.Diffs {
			fmt.Printf("Key: %s\n", diff.Key)
			fmt.Printf("Current (%s): %s\n", env, diff.Current)
			if diff.IsRedacted {
				fmt.Printf("Target (%s): (redacted)\n", targetEnv)
			} else {
				fmt.Printf("Target: (%s) %s\n", targetEnv, diff.Target)
			}
			fmt.Println("---")
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&vaultAddr, "addr", "", "Vault server address")
	rootCmd.PersistentFlags().StringVar(&vaultToken, "token", "", "Vault token")
	rootCmd.PersistentFlags().StringVar(&env, "env", "dev", "Current environment (dev/uat/prod)")

	rootCmd.AddCommand(compareCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
