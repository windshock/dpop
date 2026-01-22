import { SignJWT, jwtVerify } from 'jose';
import type { Env } from './env';

export type AccessTokenClaims = {
  iss: string;
  sub: string;
  aud: string;
  cnf: { jkt: string };
  iat: number;
  exp: number;
};

const ISSUER = 'dpop-login-fds';
const AUD_INGEST = 'ingest';

function secretKey(env: Env): Uint8Array {
  return new TextEncoder().encode(env.ACCESS_TOKEN_SECRET);
}

export async function issueIngestAccessToken(env: Env, userId: string, jkt: string, ttlSeconds: number = 10 * 60): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ cnf: { jkt } })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer(ISSUER)
    .setAudience(AUD_INGEST)
    .setSubject(userId)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(secretKey(env));
}

export async function verifyIngestAccessToken(env: Env, token: string): Promise<{ valid: true; claims: AccessTokenClaims } | { valid: false; reason: string }> {
  try {
    const { payload } = await jwtVerify(token, secretKey(env), { issuer: ISSUER, audience: AUD_INGEST });
    const sub = payload.sub;
    const iss = payload.iss;
    const aud = payload.aud;
    const iat = payload.iat;
    const exp = payload.exp;
    const cnf = payload.cnf as any;
    const jkt = cnf?.jkt;

    if (typeof sub !== 'string' || typeof iss !== 'string' || typeof iat !== 'number' || typeof exp !== 'number') {
      return { valid: false, reason: 'INVALID_TOKEN_PAYLOAD' };
    }
    const audStr = Array.isArray(aud) ? aud[0] : aud;
    if (typeof audStr !== 'string') return { valid: false, reason: 'INVALID_TOKEN_AUD' };
    if (typeof jkt !== 'string') return { valid: false, reason: 'MISSING_CNF_JKT' };

    return {
      valid: true,
      claims: {
        iss,
        sub,
        aud: audStr,
        cnf: { jkt },
        iat,
        exp,
      },
    };
  } catch {
    return { valid: false, reason: 'TOKEN_INVALID' };
  }
}




