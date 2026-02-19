#!/usr/bin/env bash
# cleanup.sh — stop the proxy and remove build artifacts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$ROOT_DIR/mic"
PID_FILE="$ROOT_DIR/.mic.pid"

# ── stop proxy via PID file ────────────────────────────────────────────────────
if [ -f "$PID_FILE" ]; then
    PID="$(cat "$PID_FILE")"
    if kill -0 "$PID" 2>/dev/null; then
        echo "[+] Stopping mic (PID $PID)..."
        kill "$PID"
        # Wait briefly for clean shutdown.
        for i in $(seq 1 10); do
            kill -0 "$PID" 2>/dev/null || break
            sleep 0.2
        done
        if kill -0 "$PID" 2>/dev/null; then
            echo "[!] Process still alive after 2 s — sending SIGKILL."
            kill -9 "$PID" || true
        fi
    else
        echo "[~] PID $PID is no longer running."
    fi
    rm -f "$PID_FILE"
else
    echo "[~] No PID file found."
fi

# ── catch any stray mic processes ─────────────────────────────────────────────
if pgrep -x mic >/dev/null 2>&1; then
    echo "[+] Killing remaining mic processes..."
    pkill -x mic || true
fi

# ── remove binary ──────────────────────────────────────────────────────────────
if [ -f "$BINARY" ]; then
    echo "[+] Removing binary $BINARY..."
    rm "$BINARY"
fi

echo "[+] Cleanup complete."
