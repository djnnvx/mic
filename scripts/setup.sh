#!/usr/bin/env bash
# setup.sh — build the mic binary, create a starter config, and start the proxy.
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
    "$BINARY" --config "$CONFIG" > "$ROOT_DIR/mic.log" 2>&1 &
    echo $! > "$PID_FILE"
    echo "    PID $(cat "$PID_FILE") — log: $ROOT_DIR/mic.log"
    echo "    Stop with:  scripts/cleanup.sh"
fi

# ── client-front: MitM CA hint ─────────────────────────────────────────────────
# Wait briefly for mic to write the CA files on first run.
CA_CERT="$ROOT_DIR/ca.pem"
sleep 0.5
if [ -f "$CA_CERT" ]; then
    echo ""
    echo "[i] MitM CA certificate found: $CA_CERT"
    echo "    Trust it once, then use mic as an HTTPS proxy:"
    echo ""
    echo "    curl --cacert $CA_CERT -x http://localhost:8080 https://tlsinfo.me/json"
    echo ""
    echo "    To add it to the system trust store (Debian/Ubuntu/Kali):"
    echo "      sudo cp $CA_CERT /usr/local/share/ca-certificates/mic-ca.crt"
    echo "      sudo update-ca-certificates"
fi
