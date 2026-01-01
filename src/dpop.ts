import { JWK, jwtVerify, importJWK, SignJWT } from 'jose';
import { DPoPKey, Event } from './types';

export async function verifyDPoP(dpopHeader: string, htm: string, htu: string, db: D1Database): Promise<{ valid: boolean; jkt?: string; member_id?: string }> {
  try {
    const dpop = JSON.parse(dpopHeader);
    const { jwk, typ, alg, jti, htm: dhtm, htu: dhtu, iat } = dpop;

    if (typ !== 'dpop+jwt') return { valid: false };
    if (alg !== 'ES256') return { valid: false }; // assuming ES256
    if (dhtm !== htm || dhtu !== htu) return { valid: false };

    const now = Math.floor(Date.now() / 1000);
    if (iat < now - 300 || iat > now + 60) return { valid: false }; // iat window

    // Check jti uniqueness (TTL 120s)
    const existing = await db.prepare('SELECT id FROM events WHERE jti = ? AND iat > ?').bind(jti, now - 120).first();
    if (existing) return { valid: false };

    const publicKey = await importJWK(jwk, 'ES256');
    const { payload } = await jwtVerify(dpopHeader, publicKey);

    const jkt = await calculateJkt(jwk);

    // Get registered key
    const keyRecord = await db.prepare('SELECT * FROM dpop_keys WHERE jkt = ?').bind(jkt).first() as DPoPKey | null;
    if (!keyRecord) return { valid: false };

    return { valid: true, jkt, member_id: keyRecord.member_id };
  } catch (e) {
    return { valid: false };
  }
}

export async function calculateJkt(jwk: JWK): Promise<string> {
  const thumbprint = await import('jose').then(({ calculateJwkThumbprint }) => calculateJwkThumbprint(jwk, 'sha256'));
  return thumbprint;
}

export async function registerDPoPKey(userId: string, jwk: JWK, memberId: string | undefined, db: D1Database): Promise<string> {
  const jkt = await calculateJkt(jwk);
  await db.prepare('INSERT INTO dpop_keys (id, user_id, jkt, public_key, member_id, created_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (jkt) DO UPDATE SET member_id = excluded.member_id')
    .bind(crypto.randomUUID(), userId, jkt, JSON.stringify(jwk), memberId, new Date().toISOString()).run();
  return jkt;
}