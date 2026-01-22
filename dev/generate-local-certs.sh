set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT_DIR/dev/certs"
mkdir -p "$CERT_DIR"

CA_KEY="$CERT_DIR/local-ca.key"
CA_CERT="$CERT_DIR/local-ca.crt"
SERVER_KEY="$CERT_DIR/okcashbag.local.key"
SERVER_CSR="$CERT_DIR/okcashbag.local.csr"
SERVER_CERT="$CERT_DIR/okcashbag.local.crt"
EXTFILE="$CERT_DIR/okcashbag.local.ext"

echo "==> Generating local CA (if missing)"
if [[ ! -f "$CA_KEY" || ! -f "$CA_CERT" ]]; then
  openssl genrsa -out "$CA_KEY" 4096
  openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=okcashbag-dev/OU=local/CN=okcashbag-local-dev-ca" \
    -out "$CA_CERT"
else
  echo "    CA already exists: $CA_CERT"
fi

echo "==> Generating server key + CSR"
openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/C=KR/ST=Seoul/L=Seoul/O=okcashbag-dev/OU=local/CN=login.okcashbag.local"

cat > "$EXTFILE" << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = login.okcashbag.local
DNS.2 = www.okcashbag.local
DNS.3 = m.okcashbag.local
DNS.4 = webview.okcashbag.local
DNS.5 = okcashbag.local
DNS.6 = dpop.skplanet.com
DNS.7 = www.okcashbag.com
DNS.8 = member.okcashbag.com
EOF

echo "==> Signing server cert with local CA"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -days 825 -sha256 -extfile "$EXTFILE"

echo ""
echo "Done."
echo "- CA cert (import + trust this in your OS/browser): $CA_CERT"
echo "- Server cert/key (used by local TLS proxy):"
echo "  - $SERVER_CERT"
echo "  - $SERVER_KEY"




