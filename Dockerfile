FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o vault-promoter ./cmd/cli
FROM alpine:3.18

RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /app/vault-promoter /usr/local/bin/vault-promoter
COPY .vaultconfigs.example /root/.vaultconfigs.example
RUN mkdir -p /root/.config/vault-promoter

ENTRYPOINT ["vault-promoter"]
