#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$ROOT_DIR/mic"

if [ -f "$BINARY" ]; then
    echo "[+] Removing binary..."
    rm "$BINARY"
fi

echo "[+] Done."
echo ""
echo "[i] CA files (ca.pem, ca-key.pem) are left in place."
echo "    Remove them manually if you no longer need them, and untrust the cert"
echo "    from your system store if you added it."
