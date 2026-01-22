#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/dist"
PACK_DIR="${ROOT_DIR}/audit-pack/dpop-audit-pack"

DATE_TAG="$(date +"%Y%m%d-%H%M%S")"
ZIP_PATH="${OUT_DIR}/dpop-audit-pack-${DATE_TAG}.zip"

WITH_NODE_MODULES="${WITH_NODE_MODULES:-0}"

if [[ ! -f "${ROOT_DIR}/.dev.vars" ]]; then
  echo "Missing .dev.vars."
  echo "Create it first: cp .dev.vars.example .dev.vars  (and fill in secrets)"
  exit 1
fi

mkdir -p "${OUT_DIR}"
rm -rf "${PACK_DIR}"
mkdir -p "${PACK_DIR}"

echo "==> Ensure local TLS certs exist (dev/certs)"
if [[ ! -f "${ROOT_DIR}/dev/certs/okcashbag.local.crt" || ! -f "${ROOT_DIR}/dev/certs/okcashbag.local.key" || ! -f "${ROOT_DIR}/dev/certs/local-ca.crt" ]]; then
  bash "${ROOT_DIR}/dev/generate-local-certs.sh"
fi

echo "==> Copy project files"
# Copy everything except huge/ephemeral folders and previous packs.
rsync -a \
  --exclude ".git/" \
  --exclude "dist/" \
  --exclude "audit-pack/" \
  --exclude ".wrangler/" \
  --exclude "node_modules/" \
  --exclude "dev/certs/" \
  "${ROOT_DIR}/" "${PACK_DIR}/"

# Include only the cert artifacts needed to run + trust the local CA (exclude CA private key).
mkdir -p "${PACK_DIR}/dev/certs"
cp -f "${ROOT_DIR}/dev/certs/local-ca.crt" "${PACK_DIR}/dev/certs/local-ca.crt"
cp -f "${ROOT_DIR}/dev/certs/okcashbag.local.crt" "${PACK_DIR}/dev/certs/okcashbag.local.crt"
cp -f "${ROOT_DIR}/dev/certs/okcashbag.local.key" "${PACK_DIR}/dev/certs/okcashbag.local.key"

echo "==> Optionally include node_modules (WITH_NODE_MODULES=1)"
if [[ "${WITH_NODE_MODULES}" == "1" ]]; then
  rsync -a "${ROOT_DIR}/node_modules/" "${PACK_DIR}/node_modules/"
fi

echo "==> Write audit marker"
cat > "${PACK_DIR}/AUDIT_PACK.txt" << EOF
This ZIP was generated on ${DATE_TAG}.
It includes local dev secrets from .dev.vars (DO NOT SHARE PUBLICLY).
EOF

echo "==> Create zip: ${ZIP_PATH}"
(cd "${ROOT_DIR}/audit-pack" && zip -qr "${ZIP_PATH}" "dpop-audit-pack")

echo "Done."
echo "- ZIP: ${ZIP_PATH}"
echo "- Tip: to include node_modules for offline installs, run: WITH_NODE_MODULES=1 bash dev/make-audit-zip.sh"

