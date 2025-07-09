#!/bin/bash -eu
# This script compiles project for Linux amd64 (Render-safe, dynamic linking)

wd=$(realpath -s "$(dirname "$0")/..")
mkdir -p "$GOPATH/bin/config" "$GOPATH/bin/sqlite"
cp -ruv "$wd/appdata/"* "$GOPATH/bin/config"

# If running inside Docker with no git access, set version manually
buildvers="v0.10.0"
buildtime=$(date +'%FT%T.%3NZ')  # ISO-8601 format

# Enable cgo (required for go-sqlite3), and set target
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1

# Build app dynamically (NO STATIC LINKING)
go build -o /go/bin/app -v \
  -tags="jsoniter prod full" \
  -ldflags="-s -w \
    -X 'github.com/slotopol/server/config.BuildVers=$buildvers' \
    -X 'github.com/slotopol/server/config.BuildTime=$buildtime'" \
  ./