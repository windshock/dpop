import { handleWebAuthnOptions, handleWebAuthnVerify, handleGoogleStart, handleGoogleCallback, handleDPoPRegister } from './auth';
import { verifyDPoP } from './dpop';
import { processEvent } from './fds';
import { Event, IngestResponse } from './types';

export interface Env {
  DB: D1Database;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/v1/auth/webauthn/options' && request.method === 'POST') {
      return handleWebAuthnOptions(request, env.DB);
    }
    if (path === '/v1/auth/webauthn/verify' && request.method === 'POST') {
      return handleWebAuthnVerify(request, env.DB);
    }
    if (path === '/v1/auth/google/start' && request.method === 'GET') {
      return handleGoogleStart(request);
    }
    if (path === '/v1/auth/google/callback' && request.method === 'GET') {
      return handleGoogleCallback(request, env.DB);
    }
    if (path === '/v1/dpop/register' && request.method === 'POST') {
      return handleDPoPRegister(request, env.DB);
    }
    if (path === '/v1/ingest/event' && request.method === 'POST') {
      return handleIngestEvent(request, env.DB);
    }
    if (path === '/v1/export/canonical' && request.method === 'GET') {
      return handleExportCanonical(request, env.DB);
    }
    if (path === '/' && request.method === 'GET') {
      return new Response(getLoginHTML(), { headers: { 'Content-Type': 'text/html' } });
    }

    return new Response('Not Found', { status: 404 });
  },
};

async function handleIngestEvent(request: Request, db: D1Database): Promise<Response> {
  const dpopHeader = request.headers.get('DPoP');
  if (!dpopHeader) return new Response('DPoP header required', { status: 401 });

  const body = await request.json();
  const { member_id, payload } = body;

  const verification = await verifyDPoP(dpopHeader, request.method, request.url, db);
  if (!verification.valid) return new Response('Invalid DPoP', { status: 401 });

  const event: Event = {
    id: crypto.randomUUID(),
    member_id,
    jkt: verification.jkt!,
    htm: request.method,
    htu: request.url,
    iat: JSON.parse(atob(dpopHeader.split('.')[1])).iat,
    jti: JSON.parse(atob(dpopHeader.split('.')[1])).jti,
    payload,
    created_at: new Date().toISOString()
  };

  await db.prepare('INSERT INTO events (id, member_id, jkt, htm, htu, iat, jti, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(event.id, event.member_id, event.jkt, event.htm, event.htu, event.iat, event.jti, JSON.stringify(event.payload), event.created_at).run();

  const canonical = await processEvent(event, db);

  const response: IngestResponse = {
    proof_verified: true,
    risk_score: canonical.risk_score,
    action: canonical.action,
    trust_level: canonical.trust_level,
    reason_codes: canonical.reason_codes
  };

  return new Response(JSON.stringify(response), { headers: { 'Content-Type': 'application/json' } });
}

async function handleExportCanonical(request: Request, db: D1Database): Promise<Response> {
  // Placeholder
  const events = await db.prepare('SELECT * FROM events ORDER BY created_at DESC LIMIT 10').all();
  return new Response(JSON.stringify(events.results), { headers: { 'Content-Type': 'application/json' } });
}

function getLoginHTML(): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>DPoP Login</title>
</head>
<body>
  <h1>Login</h1>
  <button onclick="loginWebAuthn()">Login with Passkey</button>
  <button onclick="loginGoogle()">Login with Google</button>
  <script>
    async function loginWebAuthn() {
      const options = await fetch('/v1/auth/webauthn/options', { method: 'POST' }).then(r => r.json());
      const credential = await navigator.credentials.create({ publicKey: options });
      const response = await fetch('/v1/auth/webauthn/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credential)
      });
      if (response.ok) {
        // Register DPoP
        const jwk = { kty: 'EC', crv: 'P-256', x: '...', y: '...' }; // Placeholder
        await fetch('/v1/dpop/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jwk, member_id: 'member123' })
        });
        alert('Logged in');
      }
    }
    function loginGoogle() {
      window.location.href = '/v1/auth/google/start';
    }
  </script>
</body>
</html>
  `;
}