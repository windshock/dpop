import { describe, expect, it } from 'vitest';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import type { JWK } from 'jose';
import type { KeyLike } from 'jose';
import { calculateJkt, verifyDPoP } from '../src/dpop';
import { nowSeconds } from '../src/utils';

type DPoPKeyRow = { jkt: string; member_id?: string; user_id: string; public_key?: string };

class MockD1Statement {
  private args: unknown[] = [];
  constructor(
    private sql: string,
    private state: {
      dpop_keys: Map<string, DPoPKeyRow>;
      dpop_replays: Map<string, { iat: number }>;
    },
  ) {}

  bind(...args: unknown[]) {
    this.args = args;
    return this;
  }

  async first(): Promise<unknown> {
    if (this.sql.includes('FROM dpop_keys')) {
      const jkt = String(this.args[0]);
      return this.state.dpop_keys.get(jkt) ?? null;
    }
    return null;
  }

  async run(): Promise<unknown> {
    if (this.sql.startsWith('DELETE FROM dpop_replays')) {
      const cutoff = Number(this.args[0]);
      for (const [jti, rec] of this.state.dpop_replays.entries()) {
        if (rec.iat < cutoff) this.state.dpop_replays.delete(jti);
      }
      return { success: true };
    }
    if (this.sql.startsWith('INSERT INTO dpop_replays')) {
      const jti = String(this.args[0]);
      const iat = Number(this.args[1]);
      if (this.state.dpop_replays.has(jti)) throw new Error('constraint failed');
      this.state.dpop_replays.set(jti, { iat });
      return { success: true };
    }
    throw new Error(`MockD1Statement.run: unhandled SQL: ${this.sql}`);
  }
}

class MockD1Database {
  state = {
    dpop_keys: new Map<string, DPoPKeyRow>(),
    dpop_replays: new Map<string, { iat: number }>(),
  };

  prepare(sql: string) {
    return new MockD1Statement(sql, this.state);
  }
}

async function makeDpopJwt(opts: { jwk: JWK; privateKey: KeyLike; htm: string; htu: string; iat: number; jti: string }) {
  return new SignJWT({ htm: opts.htm, htu: opts.htu, iat: opts.iat, jti: opts.jti })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: opts.jwk })
    .sign(opts.privateKey);
}

async function makeDpopJwtWithKid(opts: { kid: string; privateKey: KeyLike; htm: string; htu: string; iat: number; jti: string }) {
  return new SignJWT({ htm: opts.htm, htu: opts.htu, iat: opts.iat, jti: opts.jti })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', kid: opts.kid })
    .sign(opts.privateKey);
}

describe('DPoP', () => {
  it('calculateJkt matches jose thumbprint', async () => {
    const { publicKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const expected = await calculateJwkThumbprint(jwk, 'sha256');
    await expect(calculateJkt(jwk)).resolves.toBe(expected);
  });

  it('verifyDPoP validates signature, htm/htu, and registered key', async () => {
    const db = new MockD1Database() as unknown as D1Database;
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);

    // register key
    (db as any).state.dpop_keys.set(jkt, { jkt, user_id: 'user1', member_id: 'member123', public_key: JSON.stringify(jwk) });

    const htu = 'https://login.access.example.com/v1/ingest/event';
    const iat = nowSeconds();
    const jwt = await makeDpopJwt({ jwk, privateKey, htm: 'POST', htu, iat, jti: 'jti-1' });

    const result = await verifyDPoP(jwt, 'POST', htu, db);
    expect(result.valid).toBe(true);
    if (result.valid) {
      expect(result.jkt).toBe(jkt);
      expect(result.iat).toBe(iat);
      expect(result.jti).toBe('jti-1');
      expect(result.bound_member_id).toBe('member123');
    }
  });

  it('verifyDPoP rejects replay within TTL window', async () => {
    const db = new MockD1Database() as unknown as D1Database;
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);
    (db as any).state.dpop_keys.set(jkt, { jkt, user_id: 'user1', public_key: JSON.stringify(jwk) });

    const htu = 'https://login.access.example.com/v1/ingest/event';
    const iat = nowSeconds();
    const jwt = await makeDpopJwt({ jwk, privateKey, htm: 'POST', htu, iat, jti: 'jti-replay' });

    const first = await verifyDPoP(jwt, 'POST', htu, db);
    expect(first.valid).toBe(true);

    const second = await verifyDPoP(jwt, 'POST', htu, db);
    expect(second.valid).toBe(false);
    if (!second.valid) expect(second.reason).toBe('REPLAY');
  });

  it('verifyDPoP rejects htu mismatch', async () => {
    const db = new MockD1Database() as unknown as D1Database;
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);
    (db as any).state.dpop_keys.set(jkt, { jkt, user_id: 'user1', public_key: JSON.stringify(jwk) });

    const iat = nowSeconds();
    const jwt = await makeDpopJwt({
      jwk,
      privateKey,
      htm: 'POST',
      htu: 'https://login.access.example.com/v1/ingest/event',
      iat,
      jti: 'jti-htu',
    });

    const result = await verifyDPoP(jwt, 'POST', 'https://login.access.example.com/v1/ingest/other', db);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.reason).toBe('HTU_MISMATCH');
  });

  it('verifyDPoP canonicalizes htu (ignores query, normalizes host/port, trims trailing slash)', async () => {
    const db = new MockD1Database() as unknown as D1Database;
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);
    (db as any).state.dpop_keys.set(jkt, { jkt, user_id: 'user1', public_key: JSON.stringify(jwk) });

    const iat = nowSeconds();
    const proofHtu = 'https://LOGIN.ACCESS.EXAMPLE.COM:443/v1/ingest/event/?x=1';
    const reqHtu = 'https://login.access.example.com/v1/ingest/event';
    const jwt = await makeDpopJwt({ jwk, privateKey, htm: 'POST', htu: proofHtu, iat, jti: 'jti-htu-canon' });

    const result = await verifyDPoP(jwt, 'POST', reqHtu, db);
    expect(result.valid).toBe(true);
  });

  it('verifyDPoP supports kid=jkt (no jwk embedded) by looking up the registered key', async () => {
    const db = new MockD1Database() as unknown as D1Database;
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);
    (db as any).state.dpop_keys.set(jkt, { jkt, user_id: 'user1', public_key: JSON.stringify(jwk) });

    const htu = 'https://login.access.example.com/v1/ingest/event';
    const iat = nowSeconds();
    const jwt = await makeDpopJwtWithKid({ kid: jkt, privateKey, htm: 'POST', htu, iat, jti: 'jti-kid' });

    const result = await verifyDPoP(jwt, 'POST', htu, db);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.jkt).toBe(jkt);
  });
});


