import { beforeEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JWK } from 'jose';
import { calculateJkt } from '../src/dpop';
import { issueIngestAccessToken } from '../src/token';

// Mock FDS to avoid DB-heavy logic in unit tests
vi.mock('../src/fds', () => ({
  processEvent: vi.fn(async () => ({
    member_id_canonical: 'member123',
    member_id_confidence: 1,
    trust_level: 'HIGH',
    risk_score: 0,
    action: 'ALLOW',
    reason_codes: [],
  })),
}));

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

  async all(): Promise<{ results: unknown[] }> {
    return { results: [] };
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
    // events / canonical_events inserts are accepted
    if (this.sql.startsWith('INSERT INTO events')) return { success: true };
    if (this.sql.startsWith('INSERT INTO canonical_events')) return { success: true };
    return { success: true };
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

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

async function makeDpopJwt(opts: { jwk: JWK; privateKey: CryptoKey | any; htm: string; htu: string; iat: number; jti: string }) {
  return new SignJWT({ htm: opts.htm, htu: opts.htu, iat: opts.iat, jti: opts.jti })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: opts.jwk })
    .sign(opts.privateKey);
}

describe('ingest B-plan (Authorization DPoP token + DPoP proof)', () => {
  let db: any;
  let env: any;
  let worker: any;

  beforeEach(async () => {
    db = new MockD1Database();
    env = {
      DB: db as any,
      GOOGLE_CLIENT_ID: 'x',
      GOOGLE_CLIENT_SECRET: 'y',
      RP_ID: 'localhost',
      ORIGIN: 'http://localhost:8787',
      WEBAUTHN_RP_NAME: 'DPoP Login',
      ACCESS_TOKEN_SECRET: 'test-secret',
    };
    // Import after mocks
    worker = (await import('../src/index')).default;
  });

  it('rejects missing Authorization token (scheme)', async () => {
    const req = new Request('http://localhost:8787/v1/ingest/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', DPoP: 'x' },
      body: JSON.stringify({ member_id: 'member123', payload: {} }),
    });
    const res = await worker.fetch(req, env);
    const body = await res.json();
    expect(body.reason_codes).toContain('TOKEN_MISSING_OR_INVALID_SCHEME');
  });

  it('rejects missing DPoP proof', async () => {
    const token = await issueIngestAccessToken(env, 'user1', 'jkt-any');
    const req = new Request('http://localhost:8787/v1/ingest/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${token}` },
      body: JSON.stringify({ member_id: 'member123', payload: {} }),
    });
    const res = await worker.fetch(req, env);
    const body = await res.json();
    expect(body.reason_codes).toContain('PROOF_MISSING');
  });

  it('rejects forged token + unregistered key proof (UNREGISTERED_KEY)', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const jwk = (await exportJWK(publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);

    const token = await issueIngestAccessToken(env, 'attacker', jkt);
    const htu = 'http://localhost:8787/v1/ingest/event';
    const proof = await makeDpopJwt({ jwk, privateKey, htm: 'POST', htu, iat: nowSeconds(), jti: crypto.randomUUID() });

    const req = new Request(htu, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${token}`, DPoP: proof },
      body: JSON.stringify({ member_id: 'member123', payload: {} }),
    });
    const res = await worker.fetch(req, env);
    const body = await res.json();
    expect(body.reason_codes).toContain('PROOF_INVALID');
    expect(body.reason_codes).toContain('UNREGISTERED_KEY');
  });

  it('rejects token↔proof jkt mismatch', async () => {
    const htu = 'http://localhost:8787/v1/ingest/event';
    const iat = nowSeconds();

    const kpA = await generateKeyPair('ES256');
    const jwkA = (await exportJWK(kpA.publicKey)) as JWK;
    const jktA = await calculateJkt(jwkA);
    db.state.dpop_keys.set(jktA, { jkt: jktA, user_id: 'user1' });

    const kpB = await generateKeyPair('ES256');
    const jwkB = (await exportJWK(kpB.publicKey)) as JWK;
    const jktB = await calculateJkt(jwkB);
    db.state.dpop_keys.set(jktB, { jkt: jktB, user_id: 'user1' });

    const tokenA = await issueIngestAccessToken(env, 'user1', jktA);
    const proofB = await makeDpopJwt({ jwk: jwkB, privateKey: kpB.privateKey, htm: 'POST', htu, iat, jti: crypto.randomUUID() });

    const req = new Request(htu, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${tokenA}`, DPoP: proofB },
      body: JSON.stringify({ member_id: 'member123', payload: {} }),
    });
    const res = await worker.fetch(req, env);
    const body = await res.json();
    expect(body.reason_codes).toContain('TOKEN_PROOF_JKT_MISMATCH');
  });

  it('accepts valid token + registered key proof', async () => {
    const htu = 'http://localhost:8787/v1/ingest/event';
    const kp = await generateKeyPair('ES256');
    const jwk = (await exportJWK(kp.publicKey)) as JWK;
    const jkt = await calculateJkt(jwk);
    db.state.dpop_keys.set(jkt, { jkt, user_id: 'user1', member_id: 'member123' });

    const token = await issueIngestAccessToken(env, 'user1', jkt);
    const proof = await makeDpopJwt({ jwk, privateKey: kp.privateKey, htm: 'POST', htu, iat: nowSeconds(), jti: crypto.randomUUID() });

    const req = new Request(htu, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `DPoP ${token}`, DPoP: proof },
      body: JSON.stringify({ member_id: 'member123', payload: { rooted: false, emulator: false } }),
    });
    const res = await worker.fetch(req, env);
    const body = await res.json();
    expect(body.proof_verified).toBe(true);
    expect(body.action).toBe('ALLOW');
  });
});




