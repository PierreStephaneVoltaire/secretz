// Jsonnet template for Vault Gateway and VirtualService
// External variables:
// - env: environment name (dev, uat, prod)
// - host: host for the gateway (e.g., vault-dev.psvoltaire.ca)

// Import external variables
local env = std.extVar('env');
local host = std.extVar('host');

[
  {
    apiVersion: "networking.istio.io/v1",
    kind: "Gateway",
    metadata: {
      name: "vault-gateway",
      namespace: "vault-" + env
    },
    spec: {
      selector: {
        istio: "ingressgateway"
      },
      servers: [
        {
          port: {
            number: 443,
            name: "https",
            protocol: "HTTPS"
          },
          hosts: [
            host
          ],
          tls: {
            mode: "SIMPLE",
            credentialName: "aws-nlb-cert",
            httpsRedirect: false
          }
        }
      ]
    }
  },
  {
    apiVersion: "networking.istio.io/v1alpha3",
    kind: "VirtualService",
    metadata: {
      name: "vault-vs",
      namespace: "vault-" + env
    },
    spec: {
      hosts: [
        host
      ],
      gateways: [
        "vault-gateway"
      ],
      http: [
        {
          match: [
            {
              uri: {
                prefix: "/"
              }
            }
          ],
          route: [
            {
              destination: {
                host: "vault.vault-" + env + ".svc.cluster.local",
                port: {
                  number: 8200
                }
              }
            }
          ]
        }
      ]
    }
  }
]

