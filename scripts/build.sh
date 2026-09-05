#!/bin/sh
# Same four targets as `make dist`. Kept as a copy-pasteable reminder that
# each GOOS/GOARCH pair is its own binary.
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist
CGO_ENABLED=0
export CGO_ENABLED
ldflags="-s -w -X main.version=${VERSION:-0.1.0}"

GOOS=linux   GOARCH=arm64  GOARM64=v8.0 go build -trimpath -ldflags "$ldflags" -o dist/netmapd-linux-arm64 ./cmd/netmapd
GOOS=linux   GOARCH=amd64               go build -trimpath -ldflags "$ldflags" -o dist/netmapd-linux-amd64 ./cmd/netmapd
GOOS=windows GOARCH=amd64               go build -trimpath -ldflags "$ldflags" -o dist/netmapd.exe ./cmd/netmapd
GOOS=darwin  GOARCH=arm64               go build -trimpath -ldflags "$ldflags" -o dist/netmapd-darwin-arm64 ./cmd/netmapd

file dist/* 2>/dev/null || ls -l dist
