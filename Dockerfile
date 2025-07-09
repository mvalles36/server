# =========================
# 🚧 Build stage
# =========================
FROM golang:1.24-bookworm AS build

# Install build dependencies and missing Perl module for debconf
RUN apt-get update && apt-get install -y \
  ca-certificates \
  openssl \
  build-essential \
  libsqlite3-dev \
  libterm-readline-gnu-perl \
  && rm -rf /var/lib/apt/lists/*

# Fix TLS cert issues in CI/build environments
ARG cert_location=/usr/local/share/ca-certificates
RUN openssl s_client -showcerts -connect github.com:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ${cert_location}/github.crt
RUN openssl s_client -showcerts -connect proxy.golang.org:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ${cert_location}/proxy.golang.crt
RUN update-ca-certificates

# Set working directory
WORKDIR /go/src/github.com/slotopol/server

# Pre-cache Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source files
COPY . .

# Make your build script executable
RUN chmod +x ./task/*.sh

# Run the build script
RUN ./task/build-docker.sh

# =========================
# ✅ Deploy stage (glibc 2.36+)
# =========================
FROM debian:bookworm-slim

# Install runtime libraries needed by your Go binary
RUN apt-get update && apt-get install -y \
  libsqlite3-0 \
  libnss3 \
  libssl3 \
  ca-certificates \
  libterm-readline-gnu-perl \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy built binary
COPY --from=build /go/bin /go/bin

# Expose port used by your app
EXPOSE 8080

# Launch app directly (no shell wrapper)
CMD ["/go/bin/app", "web"]