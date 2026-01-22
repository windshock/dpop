#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA_CERT="${ROOT_DIR}/dev/certs/local-ca.crt"

if [[ ! -f "${CA_CERT}" ]]; then
  echo "Missing CA cert: ${CA_CERT}"
  echo "Generate it first:"
  echo "  bash dev/generate-local-certs.sh"
  exit 1
fi

echo "==> Trust local CA in macOS System keychain (requires sudo)"
echo "CA: ${CA_CERT}"
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${CA_CERT}"

echo ""
echo "Done."
echo "- Restart Chrome/Chromium completely."
echo "- Then open: https://dpop.skplanet.com:8443/"

