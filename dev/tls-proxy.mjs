import https from 'node:https';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

/**
 * Minimal HTTPS reverse proxy for local multi-domain testing.
 *
 * - Terminates TLS on :8443 with a local cert (dev/certs/okcashbag.local.crt/.key)
 * - Forwards to Wrangler dev server on http://127.0.0.1:8787
 * - Preserves Host header so the Worker can see the requested hostname.
 *
 * This is intentionally dependency-free (no express/http-proxy).
 */

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const CERT_DIR = path.join(ROOT, 'dev', 'certs');

const TLS_PORT = Number(process.env.TLS_PORT || 8443);
const TARGET_HOST = process.env.TARGET_HOST || '127.0.0.1';
const TARGET_PORT = Number(process.env.TARGET_PORT || 8787);

const certPath = process.env.TLS_CERT || path.join(CERT_DIR, 'okcashbag.local.crt');
const keyPath = process.env.TLS_KEY || path.join(CERT_DIR, 'okcashbag.local.key');

if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
  console.error('Missing TLS cert/key. Generate them first:');
  console.error('  bash dev/generate-local-certs.sh');
  process.exit(1);
}

const server = https.createServer(
  {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  },
  (req, res) => {
    const headers = { ...req.headers };
    // Ensure upstream gets correct host. (Node lowercases header names in req.headers already.)
    headers.host = headers.host || `${TARGET_HOST}:${TARGET_PORT}`;

    const upstream = http.request(
      {
        host: TARGET_HOST,
        port: TARGET_PORT,
        method: req.method,
        path: req.url,
        headers,
      },
      (upRes) => {
        res.writeHead(upRes.statusCode || 502, upRes.headers);
        upRes.pipe(res);
      },
    );

    upstream.on('error', (e) => {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`proxy error: ${String(e)}`);
    });

    req.pipe(upstream);
  },
);

server.listen(TLS_PORT, '0.0.0.0', () => {
  console.log(`TLS proxy ready: https://login.okcashbag.local:${TLS_PORT} -> http://${TARGET_HOST}:${TARGET_PORT}`);
  console.log(`(also works for https://www.okcashbag.local:${TLS_PORT}, https://m.okcashbag.local:${TLS_PORT}, https://webview.okcashbag.local:${TLS_PORT})`);
});


