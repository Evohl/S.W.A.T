#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PORT=${SWAT_PORT:-8443}
LOG_FILE=${SWAT_LOG_FILE:-"$ROOT_DIR/swat.log"}

if [[ "$EUID" -ne 0 ]]; then
	sudo -v
fi

if [[ "$EUID" -eq 0 ]]; then
	listener_line=$(ss -ltnp "sport = :$PORT" 2>/dev/null | awk 'NR > 1 {print; exit}')
else
	listener_line=$(sudo -n ss -ltnp "sport = :$PORT" 2>/dev/null | awk 'NR > 1 {print; exit}')
fi
if [[ -n "$listener_line" ]]; then
	pid=$(sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' <<<"$listener_line")
	if [[ -z "$pid" ]]; then
		echo "Port $PORT is in use, but the listener PID could not be determined." >&2
		exit 1
	fi
	if [[ "$EUID" -eq 0 ]]; then
		cmdline=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
	else
		cmdline=$(sudo -n sh -c "tr '\\0' ' ' < /proc/$pid/cmdline" 2>/dev/null || true)
	fi
	if [[ "$cmdline" != *swat* ]]; then
		echo "Refusing to stop non-SWAT process on port $PORT: $cmdline" >&2
		exit 1
	fi
	echo "Stopping SWAT PID $pid on port $PORT"
	if [[ "$EUID" -eq 0 ]]; then
		kill "$pid"
	else
		sudo -n kill "$pid"
	fi
	for _ in {1..50}; do
		if [[ "$EUID" -eq 0 ]]; then
			kill_check=(kill -0 "$pid")
		else
			kill_check=(sudo -n kill -0 "$pid")
		fi
		if ! "${kill_check[@]}" 2>/dev/null; then
			break
		fi
		sleep 0.1
	done
	if [[ "$EUID" -eq 0 ]]; then
		kill_check=(kill -0 "$pid")
	else
		kill_check=(sudo -n kill -0 "$pid")
	fi
	if "${kill_check[@]}" 2>/dev/null; then
		echo "SWAT PID $pid did not stop cleanly." >&2
		exit 1
	fi
fi

cd "$ROOT_DIR"
echo "Building current SWAT"
go build -a -o "$ROOT_DIR/swat" ./cmd/swat
echo "Starting SWAT on :$PORT"
if [[ "$PORT" == "8443" ]]; then
	if [[ "$EUID" -eq 0 ]]; then
		nohup "$ROOT_DIR/swat" >>"$LOG_FILE" 2>&1 &
	else
		sudo -n nohup "$ROOT_DIR/swat" >>"$LOG_FILE" 2>&1 &
	fi
else
	if [[ "$EUID" -eq 0 ]]; then
		SWAT_ADDR=":$PORT" nohup "$ROOT_DIR/swat" >>"$LOG_FILE" 2>&1 &
	else
		sudo -n env SWAT_ADDR=":$PORT" nohup "$ROOT_DIR/swat" >>"$LOG_FILE" 2>&1 &
	fi
fi
echo "Started SWAT PID $!"