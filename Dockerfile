# =========================
# 🚧 Build stage
# =========================
FROM golang:1.24-bookworm AS build

RUN apt-get update && apt-get install -y \
  ca-certificates \
  openssl \
  build-essential \
  libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

ARG cert_location=/usr/local/share/ca-certificates
RUN openssl s_client -showcerts -connect github.com:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ${cert_location}/github.crt
RUN openssl s_client -showcerts -connect proxy.golang.org:443 </dev/null 2>/dev/null | openssl x509 -outform PEM > ${cert_location}/proxy.golang.crt
RUN update-ca-certificates

WORKDIR /go/src/github.com/slotopol/server

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN chmod +x ./task/*.sh
RUN ./task/build-docker.sh

# =========================
# ✅ Deploy stage
# =========================
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
  libsqlite3-0 \
  libnss3 \
  libssl1.1 \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /go/bin /go/bin

EXPOSE 8080

CMD ["/go/bin/app", "web"]