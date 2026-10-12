#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOCAL_BINARY=${SWAT_DEPLOY_BINARY:-/tmp/swat-server}
REMOTE_BINARY=${SWAT_REMOTE_BINARY:-/tmp/swat-server}
REMOTE_ADDR=${SWAT_REMOTE_ADDR:-10.10.0.1:18443}
GOARCH=${GOARCH:-amd64}

if [[ $# -ne 1 || -z "$1" || "$1" == -* || "$1" == *[[:space:]]* ]]; then
	printf 'Usage: %s user@arch-test-vm\n' "$0" >&2
	exit 2
fi
REMOTE_HOST=$1

if [[ "$REMOTE_BINARY" != /* || "$REMOTE_BINARY" == *[![:alnum:]_./-]* || "$REMOTE_BINARY" == *..* ]]; then
	printf 'SWAT_REMOTE_BINARY must be an absolute path containing only letters, digits, dot, underscore, slash, or hyphen.\n' >&2
	exit 2
fi

cd "$ROOT_DIR"
echo "Building SWAT for linux/$GOARCH"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build -o "$LOCAL_BINARY" ./cmd/swat

echo "Uploading $LOCAL_BINARY to $REMOTE_HOST:$REMOTE_BINARY"
scp "$LOCAL_BINARY" "$REMOTE_HOST:$REMOTE_BINARY"

echo "Starting SWAT on $REMOTE_HOST at $REMOTE_ADDR"
printf -v REMOTE_COMMAND 'sudo env SWAT_ADDR=%q %q' "$REMOTE_ADDR" "$REMOTE_BINARY"
exec ssh -t "$REMOTE_HOST" "$REMOTE_COMMAND"
