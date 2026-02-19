#!/usr/bin/env bash
# run_integration_tests.sh — run the integration test suite.
#
# Integration tests spin up in-process TLS servers and do not require an
# external proxy instance.  They exercise the full round-trip:
#
#   client-front: client → TCP CONNECT → proxy → uTLS(Chrome120) → target
#   server-front: client → TLS → proxy (terminates) → uTLS(Chrome120) → backend
#
# Usage:
#   scripts/run_integration_tests.sh            # all packages
#   scripts/run_integration_tests.sh ./proxy/   # single package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

PACKAGES="${1:-./...}"
TIMEOUT="${INTEGRATION_TIMEOUT:-60s}"

echo "[+] Running integration tests (timeout: $TIMEOUT)..."
echo ""

(cd "$ROOT_DIR" && go test -tags integration -v -timeout "$TIMEOUT" "$PACKAGES")

echo ""
echo "[+] Done."
