# vault-promoter 

vault-promoter is a tool for debugging config drift and securely promoting secrets/configs across environments without exposing sensitive data. It enables redacted comparison, full or partial promotion, and pluggable secret stores, all while respecting existing access boundaries.
`This tool does not compare metadata such as TTL, versioning, or audit info. Use native tools for that.`

## Overview

This repository contains the configuration and tooling for:
- Managing secrets and configurations
- Promoting secrets between environments

## 🔍 Use Case

In companies with multiple environments like `dev`, `uat`, and `prod`, developers often lack read access to secrets and configurations in higher environments due to security restrictions. However, when issues arise in `uat` or `prod`, developers need a way to compare key-value configurations (including secrets) across environments to understand discrepancies—without needing to elevate privileges or involve DevOps or security teams.

Applications often store sensitive values like API keys or passwords alongside non-sensitive configuration values in `.env` files or large JSON structures. Ideally, these should be separated, but that’s not always the case. Simply exposing all values from higher environments isn’t acceptable from a security standpoint.


---

### ⚙️ Un-Opinionated Mode


- **No naming conventions or promotion flow is enforced.**
- Allows comparison of any secret or config path with any other:
    - Example: compare `/kv/app1/secrets` with `/prod/liveapp/secret`.
- **Primarily a diffing tool**:
    - Highlights missing keys, extra keys, and keys with differing values.
    - Can diff between different environments, stores, or backend types (e.g., Vault, AWS Secrets Manager, Azure Key Vault).
- **Secrets are redacted**
  - Visibility is determined by the access policies of the store itself and the redaction configuration (see `.vaultconfigs.example`).
- **Supports full-copy promotion** of secrets/configs from one location to another.

---



This tool ensures visibility and change traceability while respecting environment boundaries, helping teams debug issues faster and manage secrets/configs more securely.



### Components

1. **Vault Instances**
   - Deployed using Helm and managed by ArgoCD
   - Each environment (dev, uat, prod) has its own Vault instance
   - High availability with Raft storage
   - ~~Istio-based ingress with hostname routing~~


3. **Secret Management**
   - Path structure: `{kvStoreName}/appname/ENV/secrets` and `{kvStoreName}/appname/ENV/configs`
   - Cross-environment visibility with value redaction
   - Promotion workflow between environments

### Directory Structure

```
.
├── argocd/                 # ArgoCD configurations
├── pkg/                   # Go packages
│   └── vault/            # Vault client library
└── cmd/                   # CLI tools
    └── cli/              # Vault promoter CLI
```

## Getting Started

### Prerequisites

- Kubernetes cluster with ArgoCD installed
- Istio installed and configured
- Helm 3.x
- Go 1.21 or later


## Usage

### CLI Tool

The CLI provides flexible, unopinionated secret/config comparison and promotion across environments and stores. All operations are performed in "un-opinionated mode"—you specify exactly which environments, paths, and engines to compare.

#### Available Commands

The CLI provides flexible commands for comparing, copying, and splitting secrets/configs across environments and Vault instances:

- `compare` - For comparing secrets/configs across environments and Vault instances
- `copy` - For copying secrets/configs between environments and store types (Vault and AWS Secrets Manager)
- `split` - For extracting sensitive keys from a source path to a target path (Vault only)

#### Global Flags

These flags apply to all commands:

- `--config` (string, default: `./.vaultconfigs`)
  - Path to the vault configuration file. This file defines all environments, store types, redaction settings, and sensitive keys.
  - Example: `--config ./my_folder/.vaultconfigs`

#### Command: `compare`

Compares secrets/configs between paths, with options for comparing across different Vault instances.

```bash
vault-promoter compare <source-path> <target-path> --config <config-file> --env <source-env> --kv-engine <engine> [--target-env <target-env>] [--target-kv <target-kv>]
```

##### Required Arguments

- `<source-path>` - The full path to the source secret/config
- `<target-path>` - The full path to the target secret/config

##### Required Flags

- `--env` (string, required)
  - The source environment to use (e.g., `dev`, `uat`, `prod`, `staging`).
  - Example: `--env dev`

- `--kv-engine` (string, required)
  - The KV engine name to use in Vault for the source path.
  - Example: `--kv-engine kv` or `--kv-engine secret`

##### Optional Flags (for cross-instance comparison)

- `--target-env` (string)
  - The target environment to use when comparing across different Vault instances.
  - If omitted, the comparison is done within the same Vault instance.
  - Example: `--target-env prod`

- `--target-kv` (string)
  - The KV engine name to use in Vault for the target path.
  - If omitted, uses the same KV engine as specified in `--kv-engine`.
  - Example: `--target-kv secret`

##### Example Invocations

- Compare secrets between two paths in the same Vault instance:
  ```bash
  vault-promoter compare secret/app/config1 secret/app/config2 --config .vaultconfigs --env dev --kv-engine kv
  ```

- Compare secrets between the same path in different environments (cross-instance):
  ```bash
  vault-promoter compare secret/app/config secret/app/config --config .vaultconfigs --env dev --kv-engine kv --target-env prod
  ```

- Compare secrets between different paths and different KV engines across environments:
  ```bash
  vault-promoter compare secret/dev/app/config secret/prod/app/config --config .vaultconfigs --env dev --kv-engine kv --target-env prod --target-kv secrets
  ```

##### How Comparison Works

1. The CLI uses the `--env` parameter to determine the source environment and authenticate with that Vault instance.

2. If `--target-env` is provided, it authenticates with the target Vault instance as well.

3. The full paths are used directly as provided in the arguments:
   - Source path: The first argument (`<source-path>`)
   - Target path: The second argument (`<target-path>`)

4. For example, with the command:
   ```bash
   vault-promoter compare secret/app/config1 secret/app/config2 --env dev --kv-engine kv
   ```
   
   The CLI will compare:

#### Command: `copy`

Copies secrets/configs between environments and store types (Vault and AWS Secrets Manager).

```bash
vault-promoter copy <source-env> <secret-path> <target-env> [target-path] --config <config-file> --source-kv <source-kv> [--target-kv <target-kv>] [--overwrite] [--copy-config] [--copy-secrets] [--only-copy-keys]
```

##### Required Arguments

- `<source-env>` (string, required)
  - The source environment name as defined in the config file (e.g., `dev`, `uat`, `prod`)

- `<secret-path>` (string, required)
  - The path to the secret in the source environment

- `<target-env>` (string, required)
  - The target environment name as defined in the config file (e.g., `dev`, `uat`, `prod`)

- `[target-path]` (string, optional)
  - The path to the secret in the target environment
  - If omitted, uses the same path as the source

##### Required Flags

- `--source-kv` (string, required when source is Vault)
  - The KV engine name to use in Vault for the source path
  - Example: `--source-kv secret`

##### Optional Flags

- `--target-kv` (string, optional)
  - The KV engine name to use in Vault for the target path (only applicable when target is Vault)
  - If omitted and target is Vault, defaults to the source KV engine
  - Example: `--target-kv secret-uat`

- `--overwrite` (boolean, default: false)
  - If set, existing keys in the target will be overwritten. Otherwise, existing keys are preserved.
  - Example: `--overwrite`

- `--copy-config` (boolean, default: false)
  - Only copy configuration values (non-secret values)
  - Example: `--copy-config`

- `--copy-secrets` (boolean, default: false)
  - Only copy secret values (keys that match the redacted_keys list)
  - Example: `--copy-secrets`

- `--only-copy-keys` (boolean, default: false)
  - Only copy the keys, not the values. Values will be empty strings.
  - Example: `--only-copy-keys`

- `--dry-run` (boolean, default: false)
  - Show what would be copied without making any changes
  - Example: `--dry-run`

- `--approve` (boolean, default: false)
  - Automatically approve the copy operation without prompting
  - Example: `--approve`

- `--log-to` (string, default: `./vault-promoter-copy.log`)
  - Path to the log file for copy operations
  - Example: `--log-to /path/to/logfile.json`

##### Example Invocations

- Copy secrets between the same path in different environments:
  ```bash
  vault-promoter copy dev app/config prod --config .vaultconfigs --source-kv secret
  ```

- Copy secrets between different paths in different environments:
  ```bash
  vault-promoter copy dev app/config prod app/new-config --config .vaultconfigs --source-kv secret --target-kv secret
  ```

- Copy from Vault to AWS Secrets Manager:
  ```bash
  vault-promoter copy dev app/config staging app/config --config .vaultconfigs --source-kv secret
  ```

- Copy only configuration values (non-secret values):
  ```bash
  vault-promoter copy dev app/config prod --config .vaultconfigs --source-kv secret --copy-config
  ```

- Copy only secret values:
  ```bash
  vault-promoter copy dev app/config prod --config .vaultconfigs --source-kv secret --copy-secrets
  ```

- Copy and overwrite existing values:
  ```bash
  vault-promoter copy dev app/config prod --config .vaultconfigs --source-kv secret --overwrite
  ```

- Copy only the structure, not the values:
  ```bash
  vault-promoter copy dev app/config prod --config .vaultconfigs --source-kv secret --only-copy-keys
  ```

##### How Copy Works

1. The CLI uses the `--source-env` parameter to determine the source environment and authenticate with that store.

2. It then uses the `--target-env` parameter to authenticate with the target store.

3. The secret path is used to locate the secret in the source store:
   - For Vault: `<source-kv>/<secret-path>`
   - For AWS Secrets Manager: `<secret-path>`

4. If the target is Vault and the KV engine doesn't exist, it will be created automatically.

5. The copy operation follows these rules:
   - By default, existing keys in the target are not overwritten unless `--overwrite` is specified
   - If `--copy-config` is specified, only non-secret keys are copied
   - If `--copy-secrets` is specified, only secret keys (matching sensitive_keys) are copied
   - If `--only-copy-keys` is specified, only the keys are copied, not the values
   - When copying from AWS Secrets Manager to Vault, non-JSON secrets cannot be copied

#### Command: `split`

Splits sensitive keys from a source path to a target path, removing them from the source. Only works with JSON-formatted secrets.

```bash
vault-promoter split <source-env> <source-path> <target-path> --config <config-file> --source-kv <source-kv> [--target-env <target-env>] [--target-kv <target-kv>] [--dry-run] [--approve] [--log-to <log-file>]
```

##### Required Arguments

- `<source-env>` (string, required)
  - The source environment name as defined in the config file (e.g., `dev`, `uat`, `prod`)

- `<source-path>` (string, required)
  - The path to the secret in the source environment

- `<target-path>` (string, required)
  - The path where sensitive keys will be moved to

##### Required Flags

- `--source-kv` (string, required)
  - The KV engine name to use in Vault for the source path
  - Example: `--source-kv secret`

##### Optional Flags

- `--target-env` (string, optional)
  - The target environment name as defined in the config file
  - If omitted, defaults to the source environment
  - Example: `--target-env prod`

- `--target-kv` (string, optional)
  - The KV engine name to use in Vault for the target path
  - If omitted, defaults to the source KV engine
  - Example: `--target-kv secrets-sensitive`

- `--dry-run` (boolean, default: false)
  - Show what would be split without making any changes
  - Example: `--dry-run`

- `--approve` (boolean, default: false)
  - Automatically approve the split operation without prompting
  - Example: `--approve`

- `--log-to` (string, default: `./vault-promoter-split.log`)
  - Path to the log file for split operations
  - Example: `--log-to /path/to/logfile.json`

##### Example Invocations

- Split sensitive keys from a secret to a new location in the same KV engine:
  ```bash
  vault-promoter split dev app/config app/config-sensitive --config .vaultconfigs --source-kv secret
  ```

- Split sensitive keys to a different KV engine:
  ```bash
  vault-promoter split dev app/config app/config-sensitive --config .vaultconfigs --source-kv secret --target-kv sensitive-secrets
  ```

- Preview what would be split without making changes:
  ```bash
  vault-promoter split dev app/config app/config-sensitive --config .vaultconfigs --source-kv secret --dry-run
  ```

- Split sensitive keys with automatic approval:
  ```bash
  vault-promoter split dev app/config app/config-sensitive --config .vaultconfigs --source-kv secret --approve
  ```

##### How Split Works

1. The CLI uses the `--source-env` parameter to determine the source environment and authenticate with Vault.

2. The source secret is retrieved from `<source-kv>/<source-path>`.

3. The CLI checks if the target path already exists. If it does, the operation fails to prevent accidental overwriting.

4. The CLI identifies sensitive keys in the source based on the `sensitive_keys` list in the config file.

5. The split operation follows these steps in order (for safety):
   - First, create a new secret at the target path containing only the sensitive keys
   - Then, update the source secret to remove the sensitive keys
   - This ensures sensitive data is never lost during the operation

6. If no sensitive keys are found in the source, the operation fails.

7. All operations are logged to the specified log file in JSON format.

##### Output

- The CLI outputs a summary of the split operation, showing:
  - Number of sensitive keys moved
  - Names of the keys that were moved
   - Keys present in both but with different values (with redaction applied according to config)

##### Output

- The CLI outputs a human-readable diff, showing:
  - Keys only in source
  - Keys only in target
  - Keys present in both but with different values (redacted if sensitive)
- Redaction is controlled by `.vaultconfigs` settings:
  - `hide_secrets`: Redacts all secret values by default
  - `redact_json_values`: Redacts sensitive keys within JSON values
  - `sensitive_keys`: List of key names to redact

##### Example `.vaultconfigs.example` snippet

```json
{
  "environments": {
    "dev": {
      "url": "https://vault-dev.example.com",
      "token_env": "VAULT_SECREZ_DEV_TOKEN",
      "store": "vault"
    },
    "uat": {
      "url": "https://vault-uat.example.com",
      "token_env": "VAULT_SECREZ_UAT_TOKEN",
      "store": "vault"
    },
    "prod": {
      "url": "https://vault-prod.example.com",
      "token_env": "VAULT_SECREZ_PROD_TOKEN",
      "store": "vault"
    },
    "staging": {
      "store": "awssecretsmanager",
      "role": "arn:aws:iam::123456789012:role/role-name"
    }
  },
  "hide_secrets": true,
  "redact_json_values": false,
  "sensitive_keys": [
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "auth",
    "pwd",
    "pass",
    "apikey",
    "api_key",
    "access_key",
    "secret_key",
    "private_key",
    "cert",
    "certificate"
  ]
}
```

---

### `.vaultconfigs.example` Parameters Explained

The `.vaultconfigs.example` file defines how the CLI connects to secret stores and how it handles redaction. Here’s a breakdown of each parameter:

| Parameter                | Type      | Description |
|--------------------------|-----------|-------------|
| `environments`           | object    | A mapping of environment names (e.g., `dev`, `uat`, `prod`, `staging`) to their configuration blocks. Each environment specifies how to connect to its secret store. |
| `hide_secrets`         | boolean   | If `true`, all secret values are redacted in CLI output (e.g., replaced with `(redacted)`). If `false`, values are shown in plain text (not recommended for production). |
| `redact_json_values`     | boolean   | If `true`, keys matching `sensitive_keys` inside JSON values will also be redacted. Useful if secrets are stored as JSON blobs. |
| `sensitive_keys`          | array     | A list of key names (case-insensitive) considered sensitive. Any key matching an entry here will be redacted in CLI output. |

#### `environments` block
Each environment (e.g., `dev`, `uat`, `prod`, `staging`) can have the following fields:
- `url`: (string, Vault only) The base URL for the Vault server.
- `token_env`: (string, Vault only) The name of the environment variable that holds the Vault token for authentication.
- `store`: (string) The backend type. Supported values: `vault`, `awssecretsmanager`, etc.
- `role`: (string, AWS only) The ARN of the IAM role to assume when connecting to AWS Secrets Manager (optional, only for AWS environments).

#### Redaction settings
- `hide_secrets`: Enables or disables redaction of all secret values.
- `redact_json_values`: Enables redaction of sensitive keys inside JSON values.
- `sensitive_keys`: List of sensitive key names to redact (e.g., `password`, `token`, `key`). This applies to both top-level keys and (if enabled) keys inside JSON blobs.

**Example usage:**
- To add a new environment, add a new entry under `environments` with its connection details.
- To change which keys are redacted, modify the `redacted_keys` array.
- To disable redaction for development, set `redact_secrets` to `false` (not recommended for production).

---
## Questions
- How does redaction work? Can I override it?

- How does this authenticate to each Vault instance?

- Can I diff Vault and AWS Secrets Manager directly?

- What happens if a value is a JSON blob — does it do deep diffing?

- What prevents someone from overwriting secrets in prod by mistake?

- How should i use this?

- How are configs vs secrets identified? Can I tag or label them?

- Is there a web UI?

- Does this tool store or cache Vault credentials anywhere?

- What stores are supported beyond Vault and AWS SM?

- What happens if a key exists in the target but is not in the source during a copy?



## Development

### Building

```bash
# Build the CLI
go build -o vault-promoter cmd/cli/main.go

# Build the library
go build ./pkg/vault
```

### Testing

```bash
go test ./...
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 