# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o vault-promoter ./cmd/cli

# Final stage
FROM alpine:3.18

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/vault-promoter /usr/local/bin/vault-promoter

# Copy example config
COPY .vaultconfigs.example /root/.vaultconfigs.example

# Create a directory for configs
RUN mkdir -p /root/.config/vault-promoter

ENTRYPOINT ["vault-promoter"]
