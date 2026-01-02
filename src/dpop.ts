import type { JWK } from 'jose';
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import type { DPoPKey } from './types';
import { nowSeconds } from './utils';

export type DPoPVerifyResult =
  | { valid: true; jkt: string; bound_member_id?: string; iat: number; jti: string }
  | { valid: false; reason: string };

export async function calculateJkt(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, 'sha256');
}

export async function registerDPoPKey(
  userId: string,
  jwk: JWK,
  memberId: string | undefined,
  db: D1Database,
): Promise<string> {
  const jkt = await calculateJkt(jwk);

  const existing = (await db.prepare('SELECT * FROM dpop_keys WHERE jkt = ?').bind(jkt).first()) as DPoPKey | null;
  if (existing && existing.user_id !== userId) {
    throw new Error('DPoP key already registered to a different user');
  }

  await db
    .prepare(
      `INSERT INTO dpop_keys (id, user_id, jkt, public_key, member_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (jkt) DO UPDATE SET member_id = excluded.member_id`,
    )
    .bind(crypto.randomUUID(), userId, jkt, JSON.stringify(jwk), memberId ?? null, new Date().toISOString())
    .run();

  return jkt;
}

/**
 * Verify a DPoP proof (JWT) against RFC-like checks:
 * - htm/htu match
 * - iat window
 * - jti uniqueness (TTL 120s)
 * - signature validity
 * - key must be registered (by JWK thumbprint)
 */
export async function verifyDPoP(dpopJwt: string, htm: string, htu: string, db: D1Database): Promise<DPoPVerifyResult> {
  try {
    const protectedHeader = decodeProtectedHeader(dpopJwt);
    if (protectedHeader.typ !== 'dpop+jwt') return { valid: false, reason: 'INVALID_TYP' };
    if (!protectedHeader.jwk) return { valid: false, reason: 'MISSING_JWK' };

    const jwk = protectedHeader.jwk as JWK;
    const publicKey = await importJWK(jwk, protectedHeader.alg as string);

    const { payload } = await jwtVerify(dpopJwt, publicKey, { typ: 'dpop+jwt' });

    const pHtm = payload.htm;
    const pHtu = payload.htu;
    const pIat = payload.iat;
    const pJti = payload.jti;

    if (typeof pHtm !== 'string' || typeof pHtu !== 'string' || typeof pIat !== 'number' || typeof pJti !== 'string') {
      return { valid: false, reason: 'INVALID_PAYLOAD' };
    }

    if (pHtm.toUpperCase() !== htm.toUpperCase()) return { valid: false, reason: 'HTM_MISMATCH' };
    if (pHtu !== htu) return { valid: false, reason: 'HTU_MISMATCH' };

    const now = nowSeconds();
    if (pIat < now - 300 || pIat > now + 60) return { valid: false, reason: 'IAT_OUT_OF_WINDOW' };

    // TTL replay protection
    await db.prepare('DELETE FROM dpop_replays WHERE iat < ?').bind(now - 120).run();
    try {
      await db
        .prepare('INSERT INTO dpop_replays (jti, iat, created_at) VALUES (?, ?, ?)')
        .bind(pJti, pIat, new Date().toISOString())
        .run();
    } catch {
      return { valid: false, reason: 'REPLAY' };
    }

    const jkt = await calculateJkt(jwk);
    const keyRecord = (await db.prepare('SELECT * FROM dpop_keys WHERE jkt = ?').bind(jkt).first()) as DPoPKey | null;
    if (!keyRecord) return { valid: false, reason: 'UNREGISTERED_KEY' };

    return { valid: true, jkt, bound_member_id: keyRecord.member_id, iat: pIat, jti: pJti };
  } catch {
    return { valid: false, reason: 'INVALID_PROOF' };
  }
}