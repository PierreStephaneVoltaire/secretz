# Secret Promoter

A solution for managing Secrets and Configs across multiple environments with secret promotion capabilities.

## Overview

This repository contains the configuration and tooling for:
- Deploying Vault instances across multiple environments (dev, uat, prod)
- Managing secrets and configurations
- Promoting secrets between environments

## Architecture

### Components

1. **Vault Instances**
   - Deployed using Helm and managed by ArgoCD
   - Each environment (dev, uat, prod) has its own Vault instance
   - High availability with Raft storage
   - Istio-based ingress with hostname routing

2. **RBAC Structure**
   - Environment-specific policies

3. **Secret Management**
   - Path structure: `/appname/ENV/secret/*` and `/appname/ENV/config/*`
   - Cross-environment visibility with value redaction
   - Promotion workflow between environments

### Directory Structure

```
.
├── argocd/                 # ArgoCD configurations
│   └── apps/              # Application definitions
├── charts/                # Helm charts
│   └── vault/            # Vault Helm chart
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



### RBAC Configuration

The RBAC structure is defined in the ApplicationSet and includes:

- **Dev Environment**
  - Read access to all environments
  - Write access to dev environment
  - Redacted values for uat/prod

- **UAT Environment**
  - Read access to all environments
  - Write access to uat environment
  - Redacted values for prod

- **Prod Environment**
  - Read access to all environments
  - Write access to prod environment

## Usage

### CLI Tool

The CLI tool provides commands for managing secrets:

```bash
# Compare secrets between environments
vault-promoter compare myapp uat

# Promote secrets to another environment
vault-promoter promote myapp uat /myapp/dev/secret/database
```

### API Usage

```go
client, err := vault.NewClient("https://vault-dev.example.com", "token", vault.EnvDev)
if err != nil {
    log.Fatal(err)
}

// Compare secrets
comparison, err := client.CompareSecrets("myapp", vault.EnvUAT)
if err != nil {
    log.Fatal(err)
}

// Promote secrets
err = client.PromoteSecret("myapp", vault.EnvUAT, "/myapp/dev/secret/database")
if err != nil {
    log.Fatal(err)
}
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