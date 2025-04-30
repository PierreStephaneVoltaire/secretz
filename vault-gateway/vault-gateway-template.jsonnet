// Jsonnet template for Vault Gateway and VirtualService
// Parameters:
// - env: environment name (dev, uat, prod)
// - host: host for the gateway (e.g., vault-dev.psvoltaire.ca)

function(env, host) [
  {
    apiVersion: "networking.istio.io/v1",
    kind: "Gateway",
    metadata: {
      name: "vault-gateway",
      namespace: "vault-" + env,
      annotations: {
        "service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
        "service.beta.kubernetes.io/aws-load-balancer-internal": "0.0.0.0/0",
        "service.beta.kubernetes.io/aws-load-balancer-subnets": "subnet-0f26715c99655dc08,subnet-0452a294e59e69c1f,subnet-028c0e7290dd0a584",
        "service.beta.kubernetes.io/aws-load-balancer-ssl-cert": "arn:aws:acm:ca-central-1:429310424269:certificate/632ccd51-cdc6-453b-9f27-6133aa70685c",
        "service.beta.kubernetes.io/aws-load-balancer-ssl-ports": "https"
      }
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
          ]
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

