#!/usr/bin/env bash
# setup.sh — build the mic binary and create a starter config.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$ROOT_DIR/mic"
CONFIG="$ROOT_DIR/mic.toml"
EXAMPLE="$ROOT_DIR/mic.example.toml"
PID_FILE="$ROOT_DIR/.mic.pid"

# ── build ──────────────────────────────────────────────────────────────────────
echo "[+] Building mic..."
(cd "$ROOT_DIR" && go build -o mic .)
echo "    Binary: $BINARY"

# ── config ─────────────────────────────────────────────────────────────────────
if [ ! -f "$CONFIG" ]; then
    echo "[+] Creating mic.toml from mic.example.toml..."
    cp "$EXAMPLE" "$CONFIG"
    echo "    Edit $CONFIG before starting (set mode, fingerprint.tls.ja4, etc.)"
else
    echo "[~] mic.toml already exists — leaving it untouched."
fi

# ── start proxy ────────────────────────────────────────────────────────────────
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[~] mic is already running (PID $(cat "$PID_FILE"))."
else
    echo "[+] Starting mic in the background..."
    "$BINARY" --config "$CONFIG" &
    echo $! > "$PID_FILE"
    echo "    PID $(cat "$PID_FILE") — log: mic.log"
    echo "    Stop with:  scripts/cleanup.sh"
fi
