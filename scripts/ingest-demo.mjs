import { SignJWT, exportJWK, importJWK } from 'jose';
import fs from 'node:fs';
import path from 'node:path';

function usage() {
  console.log(`Usage:
  ACCESS_TOKEN='eyJ...' DPOP_PRIVATE_JWK='{"kty":"EC",...}' node scripts/ingest-demo.mjs [baseUrl] [memberId]

Examples:
  ACCESS_TOKEN='eyJ...' DPOP_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' node scripts/ingest-demo.mjs http://localhost:8787 1234567
`);
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function readDevVars(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const lines = fs.readFileSync(filePath, 'utf8').split(/\r?\n/);
  const out = {};
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    out[key] = value;
  }
  return out;
}

async function main() {
  const baseUrl = process.argv[2] ?? 'http://localhost:8787';
  const memberId = process.argv[3] ?? 'member123';
  const ingestUrl = new URL('/v1/ingest/event', baseUrl).toString();

  const devVarsPath = path.resolve(process.cwd(), '.dev.vars');
  const devVars = readDevVars(devVarsPath);
  const accessToken = process.env.ACCESS_TOKEN ?? devVars.ACCESS_TOKEN;
  const priv = process.env.DPOP_PRIVATE_JWK ?? devVars.DPOP_PRIVATE_JWK;
  if (!accessToken) {
    usage();
    throw new Error(`Missing ACCESS_TOKEN (set env var or add to ${devVarsPath})`);
  }
  if (!priv) {
    usage();
    throw new Error(`Missing DPOP_PRIVATE_JWK (set env var or add to ${devVarsPath})`);
  }

  const privateJwk = JSON.parse(priv);
  const privateKey = await importJWK(privateJwk, 'ES256');
  const publicJwk = await exportJWK(privateKey);
  delete publicJwk.d;

  const dpop = await new SignJWT({
    htm: 'POST',
    htu: ingestUrl,
    iat: nowSeconds(),
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
    .sign(privateKey);

  const resp = await fetch(ingestUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `DPoP ${accessToken}`,
      DPoP: dpop,
    },
    body: JSON.stringify({
      member_id: memberId,
      payload: {
        rooted: false,
        emulator: false,
        demo: true,
        ts: new Date().toISOString(),
      },
    }),
  });

  const text = await resp.text();
  console.log('status:', resp.status);
  console.log(text);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});


