import { SignJWT, exportJWK, importJWK } from 'jose';
import fs from 'node:fs';
import path from 'node:path';

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

  // "Stolen token" is a DPoP-bound token issued for some other key (jkt A)
  const stolenAccessToken = process.env.STOLEN_ACCESS_TOKEN ?? devVars.STOLEN_ACCESS_TOKEN ?? devVars.PREV_ACCESS_TOKEN;
  // "Attacker key" is a DIFFERENT (registered) DPoP private key (key B)
  const attackerPriv = process.env.ATTACKER_DPOP_PRIVATE_JWK ?? devVars.ATTACKER_DPOP_PRIVATE_JWK ?? devVars.DPOP_PRIVATE_JWK;

  if (!stolenAccessToken) throw new Error('Missing STOLEN_ACCESS_TOKEN (or set PREV_ACCESS_TOKEN / STOLEN_ACCESS_TOKEN in .dev.vars)');
  if (!attackerPriv) throw new Error('Missing ATTACKER_DPOP_PRIVATE_JWK (or set DPOP_PRIVATE_JWK in .dev.vars)');

  const privateJwk = JSON.parse(attackerPriv);
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
      Authorization: `DPoP ${stolenAccessToken}`,
      DPoP: dpop,
    },
    body: JSON.stringify({ member_id: memberId, payload: { demo: 'attack-token-mismatch', ts: new Date().toISOString() } }),
  });

  const text = await resp.text();
  console.log('status:', resp.status);
  console.log(text);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});




