# =========================
# 🚧 Build stage
# =========================
FROM golang:1.24-bookworm AS build

# Install required build dependencies
RUN apt-get update && apt-get install -y \
  ca-certificates \
  openssl \
  build-essential \
  libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

# Install root certificates for Go module support
ARG cert_location=/usr/local/share/ca-certificates
RUN openssl s_client -showcerts -connect github.com:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ${cert_location}/github.crt
RUN openssl s_client -showcerts -connect proxy.golang.org:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ${cert_location}/proxy.golang.crt
RUN update-ca-certificates

# Set working directory
WORKDIR /go/src/github.com/slotopol/server

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application code
COPY . .

# Make build script executable
RUN chmod +x ./task/*.sh

# Run your build script
RUN ./task/build-docker.sh

# =========================
# ✅ Deploy stage
# =========================
FROM debian:bullseye-slim

# Install runtime dependencies needed by your Go binary
RUN apt-get update && apt-get install -y \
  libsqlite3-0 \
  libnss3 \
  libssl1.1 \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=build /go/bin /go/bin

# Expose the HTTP port
EXPOSE 8080

# Run the app
CMD ["/go/bin/app", "web"]