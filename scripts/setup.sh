#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$ROOT_DIR/mic"
CA_CERT="$ROOT_DIR/ca.pem"
CA_KEY="$ROOT_DIR/ca-key.pem"

echo "[+] Building mic..."
(cd "$ROOT_DIR" && go build -o mic .)

echo ""
echo "[i] mic will run in client-front mode on :8080 with chrome-120 fingerprint."
echo "    MitM CA will be written to $CA_CERT on first run."
echo "    Trust it once, then use mic as a transparent HTTPS proxy:"
echo ""
echo "      curl --cacert $CA_CERT -x http://localhost:8080 https://tlsinfo.me/json"
echo ""
echo "    macOS system trust:"
echo "      sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $CA_CERT"
echo ""
echo "    Debian/Ubuntu/Kali system trust:"
echo "      sudo cp $CA_CERT /usr/local/share/ca-certificates/mic-ca.crt && sudo update-ca-certificates"
echo ""

exec "$BINARY" client \
    --listen :8080 \
    --fingerprint chrome-120 \
    --intercept-cert "$CA_CERT" \
    --intercept-key "$CA_KEY"
