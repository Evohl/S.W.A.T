#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOCAL_BINARY=${SWAT_DEPLOY_BINARY:-/tmp/swat-server}
REMOTE_HOST=${SWAT_REMOTE_HOST:-evohl@homeserver}
REMOTE_BINARY=${SWAT_REMOTE_BINARY:-/tmp/swat-server}
REMOTE_ADDR=${SWAT_REMOTE_ADDR:-10.10.0.1:18443}
GOARCH=${GOARCH:-amd64}

cd "$ROOT_DIR"
echo "Building SWAT for linux/$GOARCH"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$LOCAL_BINARY" ./cmd/swat

echo "Uploading $LOCAL_BINARY to $REMOTE_HOST:$REMOTE_BINARY"
scp "$LOCAL_BINARY" "$REMOTE_HOST:$REMOTE_BINARY"

echo "Starting SWAT on $REMOTE_HOST at $REMOTE_ADDR"
exec ssh -t "$REMOTE_HOST" "sudo SWAT_ADDR='$REMOTE_ADDR' '$REMOTE_BINARY'"
