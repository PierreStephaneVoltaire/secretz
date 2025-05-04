# Secret Promoter

A solution for managing Secrets and Configs across multiple environments with secret promotion capabilities.

## Overview

This repository contains the configuration and tooling for:
- Deploying Vault instances across multiple environments (dev, uat, prod)
- Managing secrets and configurations
- Promoting secrets between environments

## 🔍 Use Case

In companies with multiple environments like `dev`, `uat`, and `prod`, developers often lack read access to secrets and configurations in higher environments due to security restrictions. However, when issues arise in `uat` or `prod`, developers need a way to compare key-value configurations (including secrets) across environments to understand discrepancies—without needing to elevate privileges or involve DevOps or security teams.

Applications often store sensitive values like API keys or passwords alongside non-sensitive configuration values in `.env` files or large JSON structures. Ideally, these should be separated, but that’s not always the case. Simply exposing all values from higher environments isn’t acceptable from a security standpoint.

This tool provides two modes to address this challenge: an **unopinionated mode** and an **opinionated mode**.

---

### ⚙️ Unopinionated Mode

This is the flexible and generic approach:

- **No naming conventions or promotion flow is enforced.**
- Allows comparison of any secret or config path with any other:
    - Example: compare `/kv/app1/secrets` with `/prod/liveapp/secret`.
- **Primarily a diffing tool**:
    - Highlights missing keys, extra keys, and keys with differing values.
    - Can diff between different environments, stores, or backend types (e.g., Vault, AWS Secrets Manager, Azure Key Vault).
- **Secrets are redacted**
  - visibility is determined by the access policies of the store itself.
- **Does not support ad-hoc editing of secrets/configs**; users must manage changes through their own workflows.
- **Supports full-copy promotion** of secrets/configs from one location to another.

This mode is ideal for teams who already have guardrails in place and want flexible visibility without being locked into structure or process.

---

### 🔐 Opinionated Mode

This mode introduces structure, redaction, and a controlled promotion flow:

- **Assumes a consistent layout** in the key-value store:


```txt

{kvStore}/appName/dev/secrets
{kvStore}/appName/dev/configs
{kvStore}/appName/uat/secrets
{kvStore}/appName/uat/configs
...
````

- **Each environment has its own store instance** (e.g., `vault-dev`, `vault-uat`, `vault-prod`) and contains all environments' data.
  - Possible total of 18 paths per app with 3 envs and 2 categories (secrets/configs).
- **Redaction logic is enforced**:
  - When diffing secrets from higher environments, values are shown as `(redacted)` unless access is explicitly granted.
  - Only key names and diff indicators are shown to lower-privileged users.
  - **RBAC is used for redaction decisions**, not direct access.
- **Supports both intra-store and inter-store diffing**:
  - Within the same store: `vault-dev` comparing `dev` vs `uat` secrets.
  - Across stores: `vault-dev` vs `vault-prod` for the same app/env.
- **Supports controlled promotion workflows**:
  - Secrets and configs can be promoted from `dev` → `uat` → `prod`.
  - Ad-hoc editing of higher environment values is not allowed.
  - **Promotions happen from the dev store**:
    - Devs, DBAs, or DevOps can set `uat` and `prod` values in the `dev` Vault.
    - Later, the entire set of secrets/configs is promoted to the `uat` Vault.
  - Promoting to `prod` must follow the same path (`dev → uat → prod`).

This model enforces secure, structured management of secrets and configurations, aligns with change management practices, and enables developers to identify environment differences without exposing sensitive data.

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

The CLI tool provides commands for managing secrets:

```bash

Usage:
  vault-promoter [command]

Available Commands:
  compare     Compare secrets between environments
  help        Help about any command

Flags:
      --config string        Path to the vault configuration file (default "./.vaultconfigs")
      --config-path string   Path suffix to use (config, configs, secret, secrets) (default "config")
      --env string           Current environment (dev/uat/prod) (default "dev")
  -h, --help                 help for vault-promoter
      --kv-engine string     KV engine to use in Vault (default "kv")

Use "vault-promoter [command] --help" for more information about a command.

```



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