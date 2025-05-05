# vault-promoter 

A solution for managing Secrets and Configs across multiple environments with secret promotion capabilities.

## Overview

This repository contains the configuration and tooling for:
- Deploying Vault instances across multiple environments (dev, uat, prod)
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

The CLI provides a flexible command for comparing secrets/configs across environments and Vault instances:

- `compare` - For comparing secrets/configs across environments and Vault instances

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
   - Source: `secret/app/config1` in the `kv` engine using the `dev` environment
   - Target: `secret/app/config2` in the `kv` engine using the `dev` environment

5. For cross-instance comparison:
   ```bash
   vault-promoter compare secret/app/config secret/app/config --env dev --kv-engine kv --target-env prod
   ```
   
   The CLI will compare:
   - Source: `secret/app/config` in the `kv` engine using the `dev` environment
   - Target: `secret/app/config` in the `kv` engine using the `prod` environment

6. The comparison results show:
   - Keys only in source path
   - Keys only in target path
   - Keys present in both but with different values (with redaction applied according to config)

##### Output

- The CLI outputs a human-readable diff, showing:
  - Keys only in source
  - Keys only in target
  - Keys present in both but with different values (redacted if sensitive)
- Redaction is controlled by `.vaultconfigs` settings:
  - `redact_secrets`: Redacts all secret values by default
  - `redact_json_values`: Redacts sensitive keys within JSON values
  - `redacted_keys`: List of key names to redact

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
  "redact_secrets": true,
  "redact_json_values": false,
  "redacted_keys": [
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
| `redact_secrets`         | boolean   | If `true`, all secret values are redacted in CLI output (e.g., replaced with `(redacted)`). If `false`, values are shown in plain text (not recommended for production). |
| `redact_json_values`     | boolean   | If `true`, keys matching `redacted_keys` inside JSON values will also be redacted. Useful if secrets are stored as JSON blobs. |
| `redacted_keys`          | array     | A list of key names (case-insensitive) considered sensitive. Any key matching an entry here will be redacted in CLI output. |

#### `environments` block
Each environment (e.g., `dev`, `uat`, `prod`, `staging`) can have the following fields:
- `url`: (string, Vault only) The base URL for the Vault server.
- `token_env`: (string, Vault only) The name of the environment variable that holds the Vault token for authentication.
- `store`: (string) The backend type. Supported values: `vault`, `awssecretsmanager`, etc.
- `role`: (string, AWS only) The ARN of the IAM role to assume when connecting to AWS Secrets Manager (optional, only for AWS environments).

#### Redaction settings
- `redact_secrets`: Enables or disables redaction of all secret values.
- `redact_json_values`: Enables redaction of sensitive keys inside JSON values.
- `redacted_keys`: List of sensitive key names to redact (e.g., `password`, `token`, `key`). This applies to both top-level keys and (if enabled) keys inside JSON blobs.

**Example usage:**
- To add a new environment, add a new entry under `environments` with its connection details.
- To change which keys are redacted, modify the `redacted_keys` array.
- To disable redaction for development, set `redact_secrets` to `false` (not recommended for production).

---
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