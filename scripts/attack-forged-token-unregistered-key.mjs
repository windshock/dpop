import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK } from 'jose';
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

  // Attacker has server signing secret
  const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET ?? devVars.ACCESS_TOKEN_SECRET;
  if (!accessTokenSecret) throw new Error('Missing ACCESS_TOKEN_SECRET (set in .dev.vars)');

  // Attacker uses their own DPoP key (NOT registered in server) to create proof
  // If not provided, we generate a fresh keypair (guaranteed unregistered).
  const attackerPriv = process.env.ATTACKER_DPOP_PRIVATE_JWK ?? devVars.ATTACKER_DPOP_PRIVATE_JWK;
  let privateKey;
  let publicJwk;
  if (attackerPriv) {
    const privateJwk = JSON.parse(attackerPriv);
    privateKey = await importJWK(privateJwk, 'ES256');
    publicJwk = await exportJWK(privateKey);
    delete publicJwk.d;
  } else {
    const kp = await generateKeyPair('ES256');
    privateKey = kp.privateKey;
    publicJwk = await exportJWK(kp.publicKey);
  }
  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');

  // Forge token bound to attacker jkt (because attacker has server secret)
  const now = nowSeconds();
  const token = await new SignJWT({ cnf: { jkt } })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer('dpop-login-fds')
    .setAudience('ingest')
    .setSubject('attacker')
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(new TextEncoder().encode(accessTokenSecret));

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
      Authorization: `DPoP ${token}`,
      DPoP: dpop,
    },
    body: JSON.stringify({ member_id: memberId, payload: { demo: 'attack-forged-token-unregistered-key', ts: new Date().toISOString() } }),
  });

  const text = await resp.text();
  console.log('jkt (attacker):', jkt);
  console.log('status:', resp.status);
  console.log(text);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});


