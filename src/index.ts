import {
  handleDPoPEnrollStart,
  handleDPoPRegister,
  handleGoogleCallback,
  handleGoogleStart,
  handleLogout,
  handleMe,
  handleWebAuthnEnrollOptions,
  handleWebAuthnEnrollVerify,
  handleWebAuthnOptions,
  handleWebAuthnStepUpOptions,
  handleWebAuthnStepUpVerify,
  handleWebAuthnVerify,
} from './auth';
import { verifyDPoP } from './dpop';
import { processEvent } from './fds';
import { Event, IngestResponse } from './types';
import { json, readJson } from './http';

import type { Env } from './env';
import { issueIngestAccessToken, verifyIngestAccessToken } from './token';

function effectiveUrl(request: Request, env: Env): string {
  // Dev-only: when using the local TLS proxy, Wrangler sees http://... while the browser is https://...
  if (env.TRUST_PROXY_HEADERS === '1') {
    const xfProto = request.headers.get('x-forwarded-proto');
    const xfHost = request.headers.get('x-forwarded-host');
    if (xfProto && xfHost) {
      const u = new URL(request.url);
      return `${xfProto}://${xfHost}${u.pathname}${u.search}`;
    }
  }
  return request.url;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const host = request.headers.get('x-forwarded-host') || request.headers.get('host') || url.host;
    const hostname = host.split(':')[0].toLowerCase();

    // Dev-only: proxy real legacy sites and inject the SDK without modifying their codebase.
    // This lets us validate the popup + postMessage integration against production HTML/CSP.
    if (hostname === 'www.okcashbag.com' || hostname === 'member.okcashbag.com') {
      return handleLegacyUpstreamProxy(request, env, hostname);
    }

    if (path === '/v1/auth/webauthn/options' && request.method === 'POST') {
      return handleWebAuthnOptions(request, env);
    }
    if (path === '/v1/auth/webauthn/verify' && request.method === 'POST') {
      return handleWebAuthnVerify(request, env);
    }
    if (path === '/v1/auth/webauthn/enroll/options' && request.method === 'POST') {
      return handleWebAuthnEnrollOptions(request, env);
    }
    if (path === '/v1/auth/webauthn/enroll/verify' && request.method === 'POST') {
      return handleWebAuthnEnrollVerify(request, env);
    }
    if (path === '/v1/auth/google/start' && request.method === 'GET') {
      return handleGoogleStart(request, env);
    }
    if (path === '/v1/auth/google/callback' && request.method === 'GET') {
      return handleGoogleCallback(request, env);
    }
    if (path === '/v1/me' && request.method === 'GET') {
      return handleMe(request, env);
    }
    if (path === '/v1/logout' && request.method === 'POST') {
      return handleLogout(request, env);
    }
    if (path === '/v1/dpop/register' && request.method === 'POST') {
      return handleDPoPRegister(request, env);
    }
    if (path === '/v1/dpop/enroll/start' && request.method === 'POST') {
      return handleDPoPEnrollStart(request, env);
    }
    if (path === '/v1/auth/webauthn/stepup/options' && request.method === 'POST') {
      return handleWebAuthnStepUpOptions(request, env);
    }
    if (path === '/v1/auth/webauthn/stepup/verify' && request.method === 'POST') {
      return handleWebAuthnStepUpVerify(request, env);
    }
    if (path === '/v1/ingest/event' && request.method === 'POST') {
      return handleIngestEvent(request, env);
    }
    if (path === '/v1/token/issue' && request.method === 'POST') {
      return handleIssueToken(request, env);
    }
    if (path === '/v1/export/canonical' && request.method === 'GET') {
      return handleExportCanonical(request, env.DB);
    }
    if (path === '/sdk.js' && request.method === 'GET') {
      return new Response(getSdkJs(), { headers: { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (path === '/sdk/agent' && request.method === 'GET') {
      return new Response(getSdkAgentHtml(env), { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
    }
    if (path === '/' && request.method === 'GET') {
      return new Response(getLoginHTML(), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};

async function handleIngestEvent(request: Request, env: Env): Promise<Response> {
  const db = env.DB;

  const auth = request.headers.get('Authorization');
  const dpopHeader = request.headers.get('DPoP');

  if (!auth?.startsWith('DPoP ')) {
    const response: IngestResponse = {
      proof_verified: false,
      risk_score: 1,
      action: 'QUARANTINE',
      trust_level: 'LOW',
      reason_codes: ['TOKEN_MISSING_OR_INVALID_SCHEME'],
    };
    console.log('ingest:reject', { reason_codes: response.reason_codes });
    return json(response, { status: 200 });
  }
  if (!dpopHeader) {
    const response: IngestResponse = {
      proof_verified: false,
      risk_score: 1,
      action: 'QUARANTINE',
      trust_level: 'LOW',
      reason_codes: ['PROOF_MISSING'],
    };
    console.log('ingest:reject', { reason_codes: response.reason_codes });
    return json(response, { status: 200 });
  }

  const token = auth.slice('DPoP '.length).trim();
  const tokenRes = await verifyIngestAccessToken(env, token);
  if (!tokenRes.valid) {
    const response: IngestResponse = {
      proof_verified: false,
      risk_score: 1,
      action: 'QUARANTINE',
      trust_level: 'LOW',
      reason_codes: ['TOKEN_INVALID', tokenRes.reason],
    };
    console.log('ingest:reject', { reason_codes: response.reason_codes });
    return json(response, { status: 200 });
  }

  const body = await readJson<{ member_id: string; payload: any }>(request);
  const { member_id, payload } = body;

  const verification = await verifyDPoP(dpopHeader, request.method, effectiveUrl(request, env), db);
  if (!verification.valid) {
    const response: IngestResponse = {
      proof_verified: false,
      risk_score: 1,
      action: 'QUARANTINE',
      trust_level: 'LOW',
      reason_codes: ['PROOF_INVALID', verification.reason],
    };
    console.log('ingest:reject', { reason_codes: response.reason_codes });
    return json(response, { status: 200 });
  }

  if (tokenRes.claims.cnf.jkt !== verification.jkt) {
    const response: IngestResponse = {
      proof_verified: false,
      risk_score: 1,
      action: 'QUARANTINE',
      trust_level: 'LOW',
      reason_codes: ['TOKEN_PROOF_JKT_MISMATCH'],
    };
    console.log('ingest:reject', { reason_codes: response.reason_codes });
    return json(response, { status: 200 });
  }

  const event: Event = {
    id: crypto.randomUUID(),
    member_id,
    jkt: verification.jkt,
    htm: request.method,
    htu: effectiveUrl(request, env),
    iat: verification.iat,
    jti: verification.jti,
    payload,
    created_at: new Date().toISOString()
  };

  await db.prepare('INSERT INTO events (id, member_id, jkt, htm, htu, iat, jti, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(event.id, event.member_id, event.jkt, event.htm, event.htu, event.iat, event.jti, JSON.stringify(event.payload), event.created_at).run();

  const canonical = await processEvent(event, db, { bound_member_id: verification.bound_member_id });
  await db
    .prepare(
      'INSERT INTO canonical_events (id, event_id, member_id_canonical, member_id_confidence, trust_level, risk_score, action, reason_codes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .bind(
      crypto.randomUUID(),
      event.id,
      canonical.member_id_canonical,
      canonical.member_id_confidence,
      canonical.trust_level,
      canonical.risk_score,
      canonical.action,
      JSON.stringify(canonical.reason_codes),
      new Date().toISOString(),
    )
    .run();

  const response: IngestResponse = {
    proof_verified: true,
    risk_score: canonical.risk_score,
    action: canonical.action,
    trust_level: canonical.trust_level,
    reason_codes: canonical.reason_codes
  };

  return json(response, { status: 200 });
}

async function handleIssueToken(request: Request, env: Env): Promise<Response> {
  const db = env.DB;
  const authCookie = request.headers.get('Cookie') || '';
  // Reuse existing /v1/me session logic by importing via auth module would be circular; do minimal check in SQL.
  const sessionId = (authCookie.match(/(?:^|;\s*)session=([^;]+)/)?.[1] ?? '').trim();
  if (!sessionId) return json({ error: 'unauthorized' }, { status: 401 });
  const sess = (await db
    .prepare(`SELECT s.id as sid, u.id as user_id FROM sessions s JOIN users u ON u.id = s.user_id
              WHERE s.id = ? AND strftime('%s', s.expires_at) > strftime('%s','now')`)
    .bind(sessionId)
    .first()) as { user_id: string } | null;
  if (!sess) return json({ error: 'unauthorized' }, { status: 401 });

  const dpopHeader = request.headers.get('DPoP');
  if (!dpopHeader) return json({ error: 'dpop_required' }, { status: 400 });
  const verification = await verifyDPoP(dpopHeader, request.method, effectiveUrl(request, env), db);
  if (!verification.valid) return json({ error: 'invalid_dpop', reason: verification.reason }, { status: 401 });
  if (verification.user_id !== sess.user_id) return json({ error: 'key_not_owned_by_user' }, { status: 403 });

  const access_token = await issueIngestAccessToken(env, sess.user_id, verification.jkt);
  return json({ token_type: 'DPoP', access_token, expires_in: 600 }, { status: 200 });
}

function getSdkJs(): string {
  return `
(function(){
  function rand() { return Math.random().toString(16).slice(2) + Date.now().toString(16); }
  function openAgent(authorityOrigin, clientOrigin) {
    var url = authorityOrigin.replace(/\\/$/, '') + '/sdk/agent?client_origin=' + encodeURIComponent(clientOrigin);
    return window.open(url, 'dpop_agent', 'popup,width=520,height=720');
  }
  function errFrom(x) {
    if (!x) return new Error('unknown_error');
    if (x instanceof Error) return x;
    if (typeof x === 'string') return new Error(x);
    try {
      var e = new Error((x && x.code) ? String(x.code) : JSON.stringify(x));
      if (x && typeof x === 'object') { e.code = x.code; e.details = x; }
      return e;
    } catch { return new Error(String(x)); }
  }
  function createClient(opts) {
    if (!opts || !opts.authorityOrigin) throw new Error('authorityOrigin required');
    var authorityOrigin = opts.authorityOrigin.replace(/\\/$/, '');
    var context = opts.context || null;
    var popup = null;
    var pending = new Map();
    window.addEventListener('message', function(ev){
      if (ev.origin !== authorityOrigin) return;
      var data = ev.data || {};
      if (data.type !== 'DPOP_SDK_RESPONSE') return;
      var p = pending.get(data.requestId);
      if (!p) return;
      pending.delete(data.requestId);
      if (data.ok) p.resolve(data.result);
      else p.reject(errFrom(data.error || 'agent_error'));
    });
    function request(action, payload) {
      if (!popup || popup.closed) popup = openAgent(authorityOrigin, window.location.origin);
      if (!popup) return Promise.reject(new Error('POPUP_BLOCKED_OR_COOP'));
      var requestId = rand();
      var msg = { type: 'DPOP_SDK_REQUEST', requestId: requestId, action: action, payload: payload || {}, context: context };
      return new Promise(function(resolve, reject){
        pending.set(requestId, { resolve: resolve, reject: reject });
        // wait a tick for popup load
        setTimeout(function(){
          try { popup.postMessage(msg, authorityOrigin); } catch (e) { pending.delete(requestId); reject(errFrom(e)); }
        }, 250);
        setTimeout(function(){
          if (pending.has(requestId)) { pending.delete(requestId); reject(new Error('timeout')); }
        }, opts.timeoutMs || 15000);
      });
    }
    function sleep(ms){ return new Promise(function(r){ setTimeout(r, ms); }); }
    async function waitForLogin() {
      var deadline = Date.now() + (opts.loginTimeoutMs || 120000);
      while (Date.now() < deadline) {
        try {
          var st = await request('PING');
          if (st && st.logged_in) return st;
        } catch (e) {
          // ignore transient while popup is loading
        }
        await sleep(1000);
      }
      throw new Error('login_timeout');
    }
    return {
      ensureReady: function(){ return request('PING'); },
      ingestEvent: async function(ev){
        try {
          return await request('INGEST', ev);
        } catch (e) {
          if (e && (e.code === 'LOGIN_REQUIRED' || e.message === 'LOGIN_REQUIRED')) {
            await waitForLogin();
            return await request('INGEST', ev);
          }
          throw e;
        }
      },
    };
  }
  window.OkcashbagDPoP = { createClient: createClient };
})();
`;
}

function getSdkAgentHtml(env: Env): string {
  const allowed = (env.SDK_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const allowedJson = JSON.stringify(allowed);
  return `<!doctype html>
<html><head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>DPoP Agent</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 18px; }
    button { padding: 10px 14px; margin-right: 8px; margin-top: 8px; }
    pre { background: #f6f8fa; padding: 12px; overflow:auto; }
    .muted { color:#6b7280; font-size: 13px; }
  </style>
</head>
<body>
  <h2>DPoP Agent</h2>
  <div class="muted">This window holds the DPoP key and sends ingest requests on behalf of legacy sites.</div>
  <div id="status" class="muted">Loading...</div>
  <div>
    <button onclick="loginGoogle()">Login with Google</button>
    <button onclick="setupPasskey()">Set up Passkey</button>
    <button onclick="enroll()">Enroll DPoP key</button>
  </div>
  <h3>Log</h3>
  <pre id="log"></pre>
  <script>
    const allowed = ${allowedJson};
    const clientOrigin = new URL(location.href).searchParams.get('client_origin') || '';
    const logEl = document.getElementById('log');
    const statusEl = document.getElementById('status');
    function log(x){ logEl.textContent = (typeof x==='string'?x:JSON.stringify(x,null,2)) + '\\n' + logEl.textContent; }
    function okOrigin(origin){ return allowed.length===0 ? true : allowed.includes(origin); }

    function base64urlToUint8Array(base64url) {
      const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
      const pad = base64.length % 4 ? '='.repeat(4 - (base64.length % 4)) : '';
      const bin = atob(base64 + pad);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }
    function uint8ArrayToBase64url(bytes) {
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
    }
    function jsonToBase64url(obj) {
      const s = JSON.stringify(obj);
      return uint8ArrayToBase64url(new TextEncoder().encode(s));
    }
    async function sha256(bytes) {
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      return new Uint8Array(digest);
    }
    async function jwkThumbprintP256(jwk) {
      const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      const hash = await sha256(new TextEncoder().encode(canonical));
      return uint8ArrayToBase64url(hash);
    }
    function decodeJwtPayloadNoVerify(jwt) {
      try {
        const parts = jwt.split('.');
        const payloadJson = new TextDecoder().decode(base64urlToUint8Array(parts[1]));
        return JSON.parse(payloadJson);
      } catch { return null; }
    }

    async function openKeyDb() {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open('dpop-agent', 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys');
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    async function idbGet(store, key) {
      const db = await openKeyDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readonly');
        const st = tx.objectStore(store);
        const req = st.get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
    async function idbPut(store, key, value) {
      const db = await openKeyDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readwrite');
        const st = tx.objectStore(store);
        const req = st.put(value, key);
        req.onsuccess = () => resolve(true);
        req.onerror = () => reject(req.error);
      });
    }
    async function getKey() { return await idbGet('keys', 'current'); }
    async function setKey(v) { return await idbPut('keys', 'current', v); }

    function derToJoseEcdsa(sig, size) {
      const bytes = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
      if (bytes.length === size * 2) return bytes;
      let i = 0;
      if (bytes[i++] !== 0x30) throw new Error('Bad DER (seq)');
      const seqLen = bytes[i++];
      if (seqLen & 0x80) { const n = seqLen & 0x7f; i += n; }
      if (bytes[i++] !== 0x02) throw new Error('Bad DER (int r)');
      let rLen = bytes[i++]; let r = bytes.slice(i, i + rLen); i += rLen;
      if (bytes[i++] !== 0x02) throw new Error('Bad DER (int s)');
      let sLen = bytes[i++]; let s = bytes.slice(i, i + sLen); i += sLen;
      while (r.length && r[0] === 0x00) r = r.slice(1);
      while (s.length && s[0] === 0x00) s = s.slice(1);
      const out = new Uint8Array(size*2);
      out.set(r, size - r.length);
      out.set(s, size*2 - s.length);
      return out;
    }
    async function createDpopJwt(keyRef, htm, htu) {
      const now = Math.floor(Date.now() / 1000);
      const jti = crypto.randomUUID();
      const jkt = await jwkThumbprintP256(keyRef.publicJwk);
      const header = { typ: 'dpop+jwt', alg: 'ES256', kid: jkt }; // production-friendly
      const payload = { htm, htu, iat: now, jti };
      const encHeader = jsonToBase64url(header);
      const encPayload = jsonToBase64url(payload);
      const signingInput = encHeader + '.' + encPayload;
      const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyRef.privateKey, new TextEncoder().encode(signingInput));
      const rawSig = derToJoseEcdsa(new Uint8Array(sigBuf), 32);
      const encSig = uint8ArrayToBase64url(rawSig);
      return signingInput + '.' + encSig;
    }

    async function me() { return await fetch('/v1/me').then(r => r.json()).catch(()=>({logged_in:false})); }
    async function refreshStatus() {
      const m = await me();
      statusEl.textContent = m.logged_in ? ('Logged in as ' + m.user.email + (m.has_passkey ? ' (passkey OK)' : ' (no passkey)')) : 'Not logged in';
      return m;
    }
    refreshStatus();

    function loginGoogle(){ location.href = '/v1/auth/google/start'; }
    async function setupPasskey(){
      const m = await me();
      if (!m.logged_in) return log({error:'login_required'});
      // NOTE: even if has_passkey=true, it may be for a different RP_ID (e.g., you changed env.RP_ID).
      // Allow re-enrollment so users can create a passkey scoped to the current RP_ID.
      const opts = await fetch('/v1/auth/webauthn/enroll/options', { method:'POST', headers:{'Content-Type':'application/json'}, body: '{}' }).then(r=>r.json());
      if (opts.error) return log(opts);
      // reuse helper from main page: convert challenge/user.id
      opts.options.challenge = base64urlToUint8Array(opts.options.challenge);
      opts.options.user.id = base64urlToUint8Array(opts.options.user.id);
      // IMPORTANT: WebAuthn APIs require ArrayBuffer/ArrayBufferView for credential IDs.
      // The server returns base64url strings in JSON, so we must decode them.
      opts.options.excludeCredentials = (opts.options.excludeCredentials || []).map(c => ({...c, id: base64urlToUint8Array(c.id)}));
      const cred = await navigator.credentials.create({ publicKey: opts.options });
      const credential = {
        id: cred.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(cred.rawId)),
        type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(cred.response.clientDataJSON)),
          attestationObject: uint8ArrayToBase64url(new Uint8Array(cred.response.attestationObject)),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
      };
      const resp = await fetch('/v1/auth/webauthn/enroll/verify', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ credential }) }).then(r=>r.json());
      log(resp);
      await refreshStatus();
    }

    async function enroll(memberId){
      const m = await refreshStatus();
      if (!m.logged_in) return log({error:'login_required'});
      if (!m.has_passkey) await setupPasskey();
      // Start enrollment
      const enroll = await fetch('/v1/dpop/enroll/start', { method:'POST' }).then(r=>r.json());
      if (enroll.error) return log(enroll);
      // Step-up
      async function getStepupAssertion() {
        const stepupOpts = await fetch('/v1/auth/webauthn/stepup/options', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ enrollment_id: enroll.enrollment_id }) }).then(r=>r.json());
        if (stepupOpts.error) { log(stepupOpts); throw new Error('stepup_options_failed'); }
        stepupOpts.options.challenge = base64urlToUint8Array(stepupOpts.options.challenge);
        stepupOpts.options.allowCredentials = (stepupOpts.options.allowCredentials||[]).map(c => ({...c, id: base64urlToUint8Array(c.id)}));
        return await navigator.credentials.get({ publicKey: stepupOpts.options });
      }

      let assertion;
      try {
        assertion = await getStepupAssertion();
      } catch (e) {
        // Common case: user has a passkey in DB, but this device/phone doesn't have that RP's passkey yet.
        // Let them enroll a new passkey for the current RP_ID and then retry step-up once.
        log({ note: 'step-up failed; attempting passkey setup for this RP and retrying once', error: String(e) });
        await setupPasskey();
        assertion = await getStepupAssertion();
      }
      const stepupCredential = {
        id: assertion.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(assertion.rawId)),
        type: assertion.type,
        authenticatorAttachment: assertion.authenticatorAttachment,
        clientExtensionResults: assertion.getClientExtensionResults(),
        response: {
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(assertion.response.clientDataJSON)),
          authenticatorData: uint8ArrayToBase64url(new Uint8Array(assertion.response.authenticatorData)),
          signature: uint8ArrayToBase64url(new Uint8Array(assertion.response.signature)),
          userHandle: assertion.response.userHandle ? uint8ArrayToBase64url(new Uint8Array(assertion.response.userHandle)) : undefined,
        },
      };
      const stepupVerify = await fetch('/v1/auth/webauthn/stepup/verify', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ enrollment_id: enroll.enrollment_id, credential: stepupCredential }) }).then(r=>r.json());
      if (!stepupVerify.success) return log(stepupVerify);
      // Generate key and persist non-extractable private key
      const kp = await crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
      const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
      const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
      const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name:'ECDSA', namedCurve:'P-256' }, false, ['sign']);
      await setKey({ privateKey, publicJwk });
      // Enrollment proof
      const msg = new TextEncoder().encode('dpop-enroll:' + enroll.enrollment_id + ':' + enroll.challenge);
      const sigBuf = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, privateKey, msg);
      const signature = uint8ArrayToBase64url(new Uint8Array(sigBuf));
      const regBody = { jwk: publicJwk, enrollment_id: enroll.enrollment_id, proof: { signature } };
      if (memberId && typeof memberId === 'string') regBody.member_id = memberId;
      const resp = await fetch('/v1/dpop/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(regBody) }).then(r=>r.json());
      if (resp.access_token) localStorage.setItem('access_token', resp.access_token);
      if (resp.jkt) localStorage.setItem('jkt', resp.jkt);
      log(resp);
      return resp;
    }

    let lastMemberId = null;
    async function ensureTokenForIngest() {
      const keyRef = await getKey();
      if (!keyRef) await enroll(lastMemberId || undefined);
      const keyRef2 = await getKey();
      if (!keyRef2) throw new Error('no_key');

      const cur = localStorage.getItem('access_token') || '';
      if (cur) {
        const p = decodeJwtPayloadNoVerify(cur);
        const now = Math.floor(Date.now()/1000);
        if (p && typeof p.exp === 'number' && p.exp > now + 30) return { token: cur, keyRef: keyRef2 };
      }
      // Issue new token using DPoP proof (no step-up)
      const htu = location.origin + '/v1/token/issue';
      const dpop = await createDpopJwt(keyRef2, 'POST', htu);
      const issued = await fetch('/v1/token/issue', { method:'POST', headers: { 'DPoP': dpop } }).then(r=>r.json());
      if (issued.access_token) localStorage.setItem('access_token', issued.access_token);
      return { token: issued.access_token, keyRef: keyRef2 };
    }

    async function ingestViaAgent(payload) {
      try {
        if (payload && typeof payload.member_id === 'string' && payload.member_id) lastMemberId = payload.member_id;
      } catch {}
      const { token, keyRef } = await ensureTokenForIngest();
      const htu = location.origin + '/v1/ingest/event';
      const dpop = await createDpopJwt(keyRef, 'POST', htu);
      const resp = await fetch('/v1/ingest/event', {
        method:'POST',
        headers: { 'Content-Type':'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify(payload || {})
      }).then(r=>r.json());
      return resp;
    }

    window.addEventListener('message', async (ev) => {
      if (!okOrigin(ev.origin)) {
        try {
          ev.source && ev.source.postMessage({ type:'DPOP_SDK_RESPONSE', requestId: (ev.data||{}).requestId, ok:false, error:{ code:'ORIGIN_NOT_ALLOWED', origin: ev.origin } }, ev.origin);
        } catch {}
        return;
      }
      const data = ev.data || {};
      if (data.type !== 'DPOP_SDK_REQUEST') return;
      if (clientOrigin && ev.origin !== clientOrigin) return;
      const requestId = data.requestId;
      try {
        if (data.action === 'PING') {
          const m = await refreshStatus();
          ev.source.postMessage({ type:'DPOP_SDK_RESPONSE', requestId, ok:true, result:{ ready:true, logged_in:m.logged_in, has_passkey:m.has_passkey } }, ev.origin);
          return;
        }
        if (data.action === 'INGEST') {
          const body = data.payload || {};
          // Dev-only: carry legacy session context through the agent without storing it on legacy domains.
          // NOTE: In production, prefer a short-lived, server-issued session bridge token over raw cookies.
          if (data.context && typeof data.context === 'object') body.legacy_session = data.context;
          const m = await refreshStatus();
          if (!m.logged_in) throw { code:'LOGIN_REQUIRED' };
          const resp = await ingestViaAgent(body);
          ev.source.postMessage({ type:'DPOP_SDK_RESPONSE', requestId, ok:true, result: resp }, ev.origin);
          return;
        }
        throw { code:'UNKNOWN_ACTION' };
      } catch (e) {
        ev.source.postMessage({ type:'DPOP_SDK_RESPONSE', requestId, ok:false, error: (e && e.code) ? e : { message: String(e) } }, ev.origin);
      }
    });
  </script>
</body></html>`;
}

async function handleLegacyUpstreamProxy(request: Request, env: Env, hostname: string): Promise<Response> {
  // Proxy to the real upstream origin (443), but serve it under the local TLS proxy port (8443/443).
  const inUrl = new URL(request.url);
  const upstreamUrl = new URL(`https://${hostname}${inUrl.pathname}${inUrl.search}`);

  // Derive the authority origin (DPoP site) from the incoming port so this works on :8443 and :443.
  const host = request.headers.get('x-forwarded-host') || request.headers.get('host') || inUrl.host;
  const port = host.includes(':') ? ':' + host.split(':')[1] : '';
  const authorityOrigin = `https://dpop.skplanet.com${port}`;
  const localLegacyOrigin = `https://${hostname}${port}`;

  const headers = new Headers(request.headers);
  // Avoid sending hop-by-hop headers / mismatched host.
  headers.delete('host');
  headers.delete('content-length');

  // Make the upstream request look like a normal browser navigation.
  if (!headers.get('user-agent')) headers.set('user-agent', 'Mozilla/5.0');
  headers.set('accept', headers.get('accept') || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');

  const upstreamResp = await fetch(upstreamUrl.toString(), {
    method: request.method,
    headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
    redirect: 'manual',
  });

  const respHeaders = new Headers(upstreamResp.headers);
  // Rewrite upstream redirects back into the local legacy origin (so navigation stays on the proxy port).
  const loc = respHeaders.get('location');
  if (loc) {
    try {
      const locUrl = new URL(loc, upstreamUrl);
      if (locUrl.origin === upstreamUrl.origin) {
        respHeaders.set('location', `${localLegacyOrigin}${locUrl.pathname}${locUrl.search}${locUrl.hash}`);
      }
    } catch {
      // ignore invalid location
    }
  }
  // Dev-only: strip CSP to allow injected script/overlay. (We still keep other security headers.)
  respHeaders.delete('content-security-policy');
  respHeaders.delete('content-security-policy-report-only');
  // Dev-only: strip COOP/COEP/CORP to avoid breaking popup/opener/postMessage flows.
  respHeaders.delete('cross-origin-opener-policy');
  respHeaders.delete('cross-origin-embedder-policy');
  respHeaders.delete('cross-origin-resource-policy');
  // Be explicit (some environments behave better with an explicit unsafe-none).
  respHeaders.set('cross-origin-opener-policy', 'unsafe-none');
  respHeaders.delete('content-encoding');
  respHeaders.delete('content-length');

  const ct = respHeaders.get('content-type') || '';
  const shouldInject = request.method === 'GET' && ct.toLowerCase().includes('text/html');
  if (!shouldInject) {
    return new Response(upstreamResp.body, { status: upstreamResp.status, headers: respHeaders });
  }

  let html = await upstreamResp.text();

  // Remove CSP meta tags if present.
  html = html.replace(/<meta[^>]+http-equiv\\s*=\\s*['\"]Content-Security-Policy['\"][^>]*>/gi, '');
  // Remove COOP/COEP meta tags if present (these can break postMessage to popup).
  html = html.replace(/<meta[^>]+http-equiv\\s*=\\s*['\"]Cross-Origin-Opener-Policy['\"][^>]*>/gi, '');
  html = html.replace(/<meta[^>]+http-equiv\\s*=\\s*['\"]Cross-Origin-Embedder-Policy['\"][^>]*>/gi, '');

  // Early hook (must run before Next.js scripts): capture a stable-ish page identifier from Next internal streams when available.
  const nextHook = `
<script>
(function(){
  try {
    const g = globalThis;
    const f = g.__next_f || (g.__next_f = []);
    function scanStr(s) {
      if (typeof s !== 'string') return;
      const m = s.match(/"pageId":"([^"]+)"/);
      if (m) g.__dpop_next_pageId = m[1];
    }
    // scan existing buffered chunks
    try {
      for (const e of f) {
        if (Array.isArray(e) && typeof e[1] === 'string') scanStr(e[1]);
        else scanStr(e);
      }
    } catch {}
    // hook future pushes
    const origPush = f.push.bind(f);
    f.push = function(){
      try {
        for (let i = 0; i < arguments.length; i++) {
          const a = arguments[i];
          if (Array.isArray(a) && typeof a[1] === 'string') scanStr(a[1]);
          else scanStr(a);
        }
      } catch {}
      return origPush.apply(f, arguments);
    };
  } catch {}
})();
</script>
`;
  if (html.includes('</head>')) html = html.replace('</head>', `${nextHook}\n</head>`);

  const widget = `
<!-- dpop-sdk-injected (dev-only) -->
<style>
  #__dpop_widget { position: fixed; right: 12px; bottom: 12px; z-index: 2147483647;
    background: rgba(17,24,39,.92); color: #e5e7eb; border: 1px solid rgba(255,255,255,.12);
    border-radius: 12px; padding: 10px 12px; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    width: 360px; box-shadow: 0 10px 30px rgba(0,0,0,.35);
  }
  #__dpop_widget button { padding: 8px 10px; margin-right: 8px; margin-top: 8px; border-radius: 10px;
    border: 1px solid rgba(255,255,255,.16); background: rgba(255,255,255,.08); color:#e5e7eb;
  }
  #__dpop_widget pre { max-height: 180px; overflow:auto; background: rgba(0,0,0,.25); padding: 8px; border-radius: 10px; }
  #__dpop_widget .muted { color:#9ca3af; font-size: 12px; }
</style>
<div id="__dpop_widget">
  <div><b>DPoP SDK (Injected)</b> <span class="muted">dev-only</span></div>
  <div class="muted">legacy: <code>${hostname}</code></div>
  <div class="muted">authority: <code>${authorityOrigin}</code></div>
  <div>
    <button id="__dpop_ping">Open Agent / Ping</button>
    <button id="__dpop_send">Send test event</button>
    <label class="muted" style="display:inline-flex; gap:6px; align-items:center; margin-left:6px;">
      <input id="__dpop_auto" type="checkbox" checked />
      Auto
    </label>
  </div>
  <pre id="__dpop_log"></pre>
</div>
<script src="${authorityOrigin}/sdk.js"></script>
<script>
  (function(){
    const out = document.getElementById('__dpop_log');
    function log(label, obj){
      const ts = new Date().toLocaleTimeString();
      out.textContent = '['+ts+'] '+label+'\\n'+JSON.stringify(obj,null,2)+'\\n\\n'+out.textContent;
    }
    function readCookie(name) {
      try {
        const m = document.cookie.match(new RegExp('(?:^|;\\\\s*)' + name + '=([^;]*)'));
        return m ? decodeURIComponent(m[1]) : '';
      } catch { return ''; }
    }
    function safeGetLoginStore() {
      try {
        const raw = localStorage.getItem('login-store');
        if (!raw) return null;
        const parsed = JSON.parse(raw);
        const webToken = parsed && parsed.state && typeof parsed.state.webToken === 'string' ? parsed.state.webToken : '';
        const lastLoginType = parsed && parsed.state && typeof parsed.state.lastLoginType === 'string' ? parsed.state.lastLoginType : '';
        return { raw, webToken, lastLoginType };
      } catch { return null; }
    }

    const ls = safeGetLoginStore();
    const legacyCtx = {
      cookies: {
        SCOUTER: readCookie('SCOUTER'),
        SESSION: readCookie('SESSION'),
      },
      login_store: ls ? { lastLoginType: ls.lastLoginType, webToken: ls.webToken } : null,
    };
    log('Legacy auth (JS-visible)', {
      has_SCOUTER: !!legacyCtx.cookies.SCOUTER,
      has_SESSION: !!legacyCtx.cookies.SESSION,
      has_login_store: !!ls,
      has_webToken: !!(ls && ls.webToken),
      lastLoginType: ls ? ls.lastLoginType : null,
      note: 'If has_webToken=false on :8443, you can paste the token via window.__dpop_set_webtoken() (origin differs from :443).'
    });
    if (!window.OkcashbagDPoP) { log('SDK missing', {}); return; }
    const client = window.OkcashbagDPoP.createClient({ authorityOrigin: '${authorityOrigin}', timeoutMs: 20000, context: legacyCtx });

    // Dev-only helper: allow manual paste of a webToken (because :8443 localStorage != :443 localStorage).
    function promptSetWebToken() {
      const cur = safeGetLoginStore();
      const curTok = cur && cur.webToken ? cur.webToken : '';
      const v = prompt('Paste webToken to store in localStorage[login-store] for this origin', curTok);
      if (!v) return;
      try {
        const curRaw = localStorage.getItem('login-store');
        let parsed = curRaw ? JSON.parse(curRaw) : { state: {}, version: 1 };
        parsed.state = parsed.state || {};
        parsed.state.webToken = v;
        localStorage.setItem('login-store', JSON.stringify(parsed));
        log('login-store updated', { has_webToken: true });
      } catch (e) {
        log('login-store update failed', { error: String(e) });
      }
    }
    window.__dpop_set_webtoken = promptSetWebToken;
    document.getElementById('__dpop_ping').onclick = async () => {
      try { log('PING', await client.ensureReady()); } catch(e){ log('PING error', (e && typeof e === 'object') ? e : { error:String(e) }); }
    };
    function base64urlToString(b64u) {
      try {
        const base64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
        const pad = base64.length % 4 ? '='.repeat(4 - (base64.length % 4)) : '';
        return atob(base64 + pad);
      } catch { return ''; }
    }
    function decodeJwtPayloadNoVerify(jwt) {
      try {
        const parts = (jwt || '').split('.');
        if (parts.length < 2) return null;
        const json = base64urlToString(parts[1]);
        return JSON.parse(json);
      } catch { return null; }
    }
    function canonicalMemberId() {
      // Prefer legacy webToken claims if available.
      try {
        const ls = legacyCtx && legacyCtx.login_store;
        const tok = ls && ls.webToken ? String(ls.webToken) : '';
        if (tok) {
          const p = decodeJwtPayloadNoVerify(tok);
          // okcashbag webToken: prefer encryptMbrId (encrypted member id) if present.
          if (p && typeof p.encryptMbrId === 'string' && p.encryptMbrId) return p.encryptMbrId.replace(/[^a-zA-Z0-9_-]/g, '_');
          // Fallbacks
          // sample tokens may also contain "key": "<hex...>"
          if (p && typeof p.key === 'string' && p.key) return p.key.replace(/[^a-zA-Z0-9_-]/g, '_');
          if (p && typeof p.sub === 'string' && p.sub) return p.sub.replace(/[^a-zA-Z0-9_-]/g, '_');
        }
      } catch {}
      // Fallback: sanitize hostname (dots are invalid for our demo rule).
      return String(location.hostname).replace(/[^a-zA-Z0-9_-]/g, '_') + '_user';
    }

    function readNextPageId() {
      try {
        return (window.__dpop_next_pageId) ||
          (window.__NEXT_DATA__ && window.__NEXT_DATA__.page) ||
          String(location.pathname || '');
      } catch { return String(location.pathname || ''); }
    }

    // --- Auto event capture (dev/demo) ---
    const AUTO_SAMPLE_RATE = 0.25; // 25%
    const AUTO_MAX_PER_MIN = 8;
    const AUTO_MIN_INTERVAL_MS = 1200;
    let lastSentAt = 0;
    let sentTimes = [];

    function autoEnabled() {
      const el = document.getElementById('__dpop_auto');
      return !!(el && el.checked);
    }
    function withinWidget(target) {
      try { return !!(target && target.closest && target.closest('#__dpop_widget')); } catch { return false; }
    }
    function shouldSendAuto() {
      if (!autoEnabled()) return false;
      if (Math.random() > AUTO_SAMPLE_RATE) return false;
      const now = Date.now();
      if (now - lastSentAt < AUTO_MIN_INTERVAL_MS) return false;
      sentTimes = sentTimes.filter(t => now - t < 60000);
      if (sentTimes.length >= AUTO_MAX_PER_MIN) return false;
      return true;
    }
    async function sendAuto(event_type, data) {
      if (!shouldSendAuto()) return;
      const now = Date.now();
      lastSentAt = now;
      sentTimes.push(now);
      try {
        const payload = {
          member_id: canonicalMemberId(),
          payload: {
            action: 'auto',
            event_type,
            page_id: readNextPageId(),
            path: location.pathname,
            href: location.href,
            referrer: document.referrer || '',
            ts: now,
            ...data,
          },
        };
        const r = await client.ingestEvent(payload);
        log('AUTO ingest', { event_type, ok: true, action: r.action, risk_score: r.risk_score, reason_codes: r.reason_codes });
      } catch (e) {
        log('AUTO ingest error', (e && typeof e === 'object') ? e : { error: String(e) });
      }
    }

    // Hook existing telemetry (e.g. Next.js chunk function 'trackLog' -> 'window.RAKE.track(...)')
    // so we can piggyback on the site's canonical action/page/session identifiers.
    function hookRakeOnce() {
      try {
        const w = window;
        if (!w.RAKE || typeof w.RAKE.track !== 'function') return false;
        if (w.__dpop_rake_hooked) return true;
        w.__dpop_rake_hooked = true;
        const orig = w.RAKE.track.bind(w.RAKE);
        w.__dpop_rake_track_orig = orig;

        w.RAKE.track = function(args) {
          try {
            const p = args && args.payload ? args.payload : null;
            // best-effort extraction across possible payload shapes
            const action_id = p && (p.action_id || p.actionId) ? String(p.action_id || p.actionId) : '';
            const page_id = p && (p.page_id || p.pageId) ? String(p.page_id || p.pageId) : readNextPageId();
            const session_id = p && (p.session_id || p.sessionId) ? String(p.session_id || p.sessionId) : '';
            const body = p && (p._$body || p.body) ? (p._$body || p.body) : null;
            // Treat these as high-signal events; still respect rate limits but don't sample them away.
            const now = Date.now();
            sentTimes = sentTimes.filter(t => now - t < 60000);
            if (now - lastSentAt >= 300 && sentTimes.length < AUTO_MAX_PER_MIN) {
              lastSentAt = now;
              sentTimes.push(now);
              client.ingestEvent({
                member_id: canonicalMemberId(),
                payload: {
                  action: 'telemetry',
                  event_type: 'rake_track',
                  action_id,
                  page_id,
                  session_id,
                  path: location.pathname,
                  href: location.href,
                  ts: now,
                  body,
                }
              }).then((r) => {
                log('RAKE→DPoP', { action_id, page_id, ok: true, action: r.action, risk_score: r.risk_score, reason_codes: r.reason_codes });
              }).catch((e) => {
                log('RAKE→DPoP error', (e && typeof e === 'object') ? e : { error: String(e) });
              });
            }
          } catch {}
          return orig(args);
        };
        log('Hooked RAKE.track', { ok: true });
        return true;
      } catch {
        return false;
      }
    }

    // RAKE may load after hydration; poll a bit.
    (function pollHook(){
      let tries = 0;
      const max = 40; // ~20s
      const t = setInterval(() => {
        tries++;
        if (hookRakeOnce() || tries >= max) clearInterval(t);
      }, 500);
    })();

    document.getElementById('__dpop_send').onclick = async () => {
      try {
        const payload = { member_id: canonicalMemberId(), payload: { action: 'injected_test_event', page_id: readNextPageId(), path: location.pathname, ts: Date.now() } };
        log('INGEST request', payload);
        const r = await client.ingestEvent(payload);
        log('INGEST response', r);
      } catch(e){ log('INGEST error', (e && typeof e === 'object') ? e : { error:String(e) }); }
    };

    // Clicks on buttons/links (capture phase).
    document.addEventListener('click', (ev) => {
      const t = ev.target;
      if (withinWidget(t)) return;
      const el = t && t.closest ? t.closest('a,button,[role=\"button\"],input[type=\"button\"],input[type=\"submit\"]') : null;
      const tag = el ? el.tagName.toLowerCase() : (t && t.tagName ? t.tagName.toLowerCase() : 'unknown');
      const id = el && el.id ? el.id : '';
      const cls = el && el.className && typeof el.className === 'string' ? el.className.split(' ').slice(0,3).join('.') : '';
      const href = el && el.tagName && el.tagName.toLowerCase() === 'a' ? (el.getAttribute('href') || '') : '';
      sendAuto('click', { tag, id, cls, href });
    }, true);

    // Form submits
    document.addEventListener('submit', (ev) => {
      const t = ev.target;
      if (withinWidget(t)) return;
      const form = t && t.tagName ? t : null;
      const action = form && form.getAttribute ? (form.getAttribute('action') || '') : '';
      const method = form && form.getAttribute ? (form.getAttribute('method') || 'get') : 'get';
      sendAuto('submit', { action, method });
    }, true);

    // Navigation: popstate + pushState/replaceState hooks
    window.addEventListener('popstate', () => sendAuto('nav', { kind: 'popstate' }));
    (function(){
      const _push = history.pushState;
      const _repl = history.replaceState;
      history.pushState = function(){ const r = _push.apply(this, arguments); sendAuto('nav', { kind: 'pushState' }); return r; };
      history.replaceState = function(){ const r = _repl.apply(this, arguments); sendAuto('nav', { kind: 'replaceState' }); return r; };
    })();

    log('Injected ready', { ok:true });
  })();
</script>
`;

  if (html.includes('</body>')) html = html.replace('</body>', `${widget}\n</body>`);
  else if (html.includes('</head>')) html = html.replace('</head>', `</head>\n${widget}`);
  else html = html + widget;

  return new Response(html, { status: upstreamResp.status, headers: respHeaders });
}

async function handleExportCanonical(request: Request, db: D1Database): Promise<Response> {
  const rows = await db.prepare('SELECT * FROM canonical_events ORDER BY created_at DESC LIMIT 10').all();
  return json(rows.results, { status: 200 });
}

function getLoginHTML(): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <title>DPoP Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    input { padding: 10px; width: 100%; max-width: 420px; }
    textarea { padding: 10px; width: 100%; max-width: 640px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    button { padding: 10px 14px; margin-right: 8px; margin-top: 8px; }
    pre { background: #f6f8fa; padding: 12px; overflow: auto; }
    .row { margin: 12px 0; }
    .grid { display: grid; grid-template-columns: 1fr; gap: 18px; align-items: start; }
    .card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; }
    .muted { color: #6b7280; font-size: 13px; }
    .banner { border: 1px solid #e5e7eb; border-radius: 14px; padding: 14px 16px; background: linear-gradient(180deg, #ffffff 0%, #fbfdff 100%); margin-bottom: 18px; }
    .banner h2 { margin: 0 0 6px 0; font-size: 16px; }
    .pill { display: inline-block; font-size: 12px; padding: 3px 8px; border-radius: 999px; border: 1px solid #e5e7eb; background: #fff; color: #374151; margin-right: 6px; }
    .flow { display: grid; grid-template-columns: 1fr; gap: 10px; margin-top: 10px; }
    .flow-step { border: 1px solid #e5e7eb; background: #fff; border-radius: 12px; padding: 12px; }
    .flow-step .title { font-weight: 650; margin-bottom: 4px; }
    .flow-step code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    .arrow { color: #9ca3af; font-size: 12px; margin: -2px 0 -2px 6px; }
    details { border: 1px dashed #e5e7eb; border-radius: 12px; padding: 10px 12px; background: #fff; }
    summary { cursor: pointer; font-weight: 650; color: #374151; }
  </style>
</head>
<body>
  <h1>DPoP Demo</h1>
  <div class="banner">
    <h2>🧭 전체 흐름(요약)</h2>
    <div class="muted" style="margin-bottom: 8px;">
      <span class="pill">Remote signing</span>
      <span class="pill">Key stays on DPoP origin</span>
      <span class="pill">Events → Ingest → FDS</span>
    </div>
    <div class="muted">
      핵심: <b>DPoP private key는 dpop.skplanet.com(origin)에서만 보관</b>되고, 레가시 페이지는 <b>서명/인제스트 요청만</b> 합니다.
    </div>
    <div class="muted" style="margin-top: 8px;">
      <b>왜 DPoP를 이 구조로 하나요?</b>
      기존 Bearer 토큰은 한 번 유출되면(로그/확장프로그램/중간자/메모리 등) <b>그대로 재사용</b>되기 쉽습니다.
      DPoP는 매 요청마다 “나는 이 키를 정말 가지고 있다”는 <b>서명 증명(proof)</b>을 함께 보내게 만듭니다.
      그리고 토큰 안에도 “이 토큰은 어떤 키에 묶여 있는지”(<code>cnf.jkt</code>)가 들어 있어서,
      서버는 <b>토큰에 적힌 키</b>와 <b>요청에서 증명한 키</b>가 같은지 확인할 수 있습니다.
      그래서 공격자는 토큰만 훔쳐서는 재사용이 어렵고 <b>그 키까지</b> 가져와야 합니다.
      이 데모 구조는 키를 레가시 서버/페이지에 두지 않고 <b>dpop.skplanet.com 전용 origin</b>에 격리(원격 서명)해서,
      레가시 수정이 어려운 환경에서도 단계적으로 도입(옵션 A→B)할 수 있게 합니다.
    </div>
    <div class="muted" style="margin-top: 8px;">
      <b>내부자 위협 관점(요약)</b>
      중앙에서 모든 서명을 대행하는 구조는 “서명 권한”이 내부자에게 집중될 수 있습니다.
      반대로 이 구조는 private key를 사용자/에이전트 쪽(비추출 CryptoKey)으로 분산해 중앙 운영자가 임의로 “사용자 대신 서명”하기 어렵게 만들고,
      서버는 검증/정책/차단(등록 해지, TTL, 레이트리밋 등)에 집중하는 방향입니다.
    </div>
    <div class="muted" style="margin-top: 8px;">
      <b>왜 KYC가 있는데도 Passkey를 쓰나?</b>
      KYC는 “기기 전부 분실/고위험 분쟁” 같은 예외 상황의 <b>최후 복구</b> 수단(비싸고 느림)이고,
      Passkey(WebAuthn)는 평소에 DPoP 키 등록/민감 액션을 <b>즉시·저비용·피싱 저항성</b> 있게 step-up 하는 수단입니다.
    </div>
    <div class="flow">
      <div class="flow-step">
        <div class="title">1) Legacy (www/member) + injected SDK</div>
        <div class="muted">사용자 행동(click/submit/navigation) + 컨텍스트(member_id 등)를 수집하고, <code>postMessage</code>로 DPoP Agent에 “서명+전송”을 요청</div>
      </div>
      <div class="arrow">↓</div>
      <div class="flow-step">
        <div class="title">2) DPoP Agent (dpop.skplanet.com)</div>
        <div class="muted">DPoP private key를 <b>IndexedDB의 non-extractable CryptoKey</b>로 저장(내보내기 불가). 필요 시 <b>Passkey(WebAuthn)</b>로 step-up</div>
      </div>
      <div class="arrow">↓</div>
      <div class="flow-step">
        <div class="title">3) Protected API (검증 위치는 2가지 옵션)</div>
        <div class="muted">
          공통: <code>Authorization: DPoP &lt;access_token&gt;</code> + <code>DPoP: &lt;proof JWT&gt;</code>를 매 요청에 포함.
          리소스 서버는 proof(htu/htm/iat/jti) 검증 + token의 <code>cnf.jkt</code> 바인딩을 확인해야 합니다.
          <div style="margin-top: 8px;">
            <b>옵션 A (레가시 수정 최소)</b>: DPoP 전용 Worker/Gateway가 DPoP를 검증하고, 레가시에는 내부 신뢰 헤더/브리지로 전달
          </div>
          <div style="margin-top: 6px;">
            <b>옵션 B (레가시 수정 가능)</b>: 레가시 API(또는 앞단 게이트웨이)가 직접 DPoP를 검증하여 “DPoP로 보호된 API”를 구현
          </div>
        </div>
      </div>
    </div>

    <details style="margin-top: 12px;">
      <summary>기기를 모두 분실할 경우(모든 Passkey 분실) — 운영 단순화 가이드</summary>
      <div class="muted" style="margin-top: 10px;">
        Passkey/WebAuthn은 피싱에 강하지만, <b>모든 등록 기기를 분실</b>하면 “기기 소유(possession)” 자체를 증명할 수 없어서 복구 정책이 필요합니다.
        정교한 위험평가 운영이 어렵다면 안전한 쪽으로 단순화할 수 있습니다(대신 UX/콜센터 비용 증가).
      </div>
      <div class="muted" style="margin-top: 6px;">
        (정리) <b>Passkey는 “상시 step-up”</b>, <b>KYC는 “최후 복구”</b>로 역할이 다릅니다.
      </div>
      <ul class="muted" style="margin-top: 10px;">
        <li><b>패턴 1 (가장 단순/안전)</b>: Passkey 전부 분실 → <b>무조건 고객센터 KYC</b>(또는 오프라인/강한 본인확인)</li>
        <li><b>패턴 2</b>: <b>기존 신뢰 세션이 있을 때만</b> self-recovery 허용(새 passkey/새 DPoP 키 <b>추가등록</b>). 세션이 없으면 KYC</li>
        <li><b>패턴 3</b>: KMC(통신사 본인확인)는 “리셋”이 아니라 <b>짧은 임시 접근</b>만 허용(예: 10분) → 그 안에 passkey 추가등록, 실패 시 KYC</li>
      </ul>
      <div class="muted" style="margin-top: 6px;">
        <b>KMC vs KYC</b>:
        KMC(통신사 본인확인)는 “회선/번호 기반” 원격 본인확인이라 편하지만 SIM-swap/명의도용 리스크가 있고,
        KYC(강한 신원확인/고객센터)는 신분증/계좌/ARS/영상/대면 등 <b>더 강한 절차</b>로 보통 KMC보다 상위 등급으로 운영됩니다.
      </div>
      <div class="muted" style="margin-top: 6px;">
        <b>SMS OTP</b>는 구현은 쉽지만 SIM-swap 등 리스크가 있어 복구/리셋 같은 고위험 행위에는 보통 <b>단독 수단으로 권장되지 않습니다</b>
        (알림/저위험 보조, 또는 KMC/KYC와 조합 권장).
      </div>
      <div class="muted" style="margin-top: 8px;">
        최소 운영 정책(2줄): <b>기기 분실 → KYC</b>, <b>기기 살아있음(기존 세션 있음) → self-serve로 추가등록</b>
      </div>
    </details>

    <details style="margin-top: 10px;">
      <summary>FAQ / 검토 메모 (사람들이 자주 묻는 포인트)</summary>
      <div class="muted" style="margin-top: 10px;">
        아래는 데모를 처음 보는 분들이 보통 궁금해하는 “현실 운영 관점” Q&A 입니다. (긴 설명은 접어두고 필요할 때만 펼쳐서 봅니다)
      </div>
      <div class="muted" style="margin-top: 10px;">
        <b>Q. DPoP는 누가 검증해야 하나요?</b><br/>
        A. 원칙적으로 “보호하려는 API(리소스 서버)”가 <code>Authorization</code>(토큰) + <code>DPoP</code>(proof)를 함께 검증해야 합니다.
        레가시를 못 고치면(옵션 A) 앞단 Worker/Gateway가 검증을 대행하고, 레가시에는 내부 신뢰 헤더/브리지로 전달합니다.
      </div>
      <div class="muted" style="margin-top: 10px;">
        <b>Q. KYC가 있는데 Passkey를 왜 쓰나요?</b><br/>
        A. KYC는 예외 상황(전부 분실/분쟁)의 “최후 복구”이고, Passkey는 평소의 step-up(키 등록/민감 액션)을 빠르고 안전하게 처리합니다.
      </div>
      <div class="muted" style="margin-top: 10px;">
        <b>Q. “키관리서버(KMS/HSM) + 키 로테이션”이면 내부자 위협에 대응 가능한가요?</b><br/>
        A. 유출 면적/피해 기간을 줄이는 데는 도움이 되지만, 내부자가 “서명 권한”을 가지면 로테이션만으로는 근본 해결이 아닙니다.
        내부자 리스크는 권한 분리/승인/감사/정책(레이트리밋, 범위 제한)으로 줄입니다.
      </div>
      <div class="muted" style="margin-top: 10px;">
        <b>Q. access_token을 DB에 저장해서 상태 기반으로 제어하면 더 안전한가요?</b><br/>
        A. 즉시 폐기(revoke) 같은 “운영 통제”에는 유리하지만, 이것만으로 DPoP/Passkey가 주는 효과(특히 <b>토큰 탈취 후 재사용 방지</b>)를 대체하진 못합니다.
        stateful 토큰은 보통 “언제든 서버가 끊을 수 있다”에 강점이 있고, DPoP는 “토큰이 새더라도 키가 없으면 재사용이 어렵다”에 강점이 있습니다.
        <br/>또한 DB에 저장이 필요하다면 토큰 “원문”을 저장하기보다는 보통 <b>reference token(opaque)</b> 또는 <b>jti/해시 기반</b>으로 설계합니다(유출 시 재사용 위험 감소).
      </div>
      <div class="muted" style="margin-top: 10px;">
        <b>Q. 사용자/에이전트 키(비추출 CryptoKey) 모델은 왜 내부자에 유리한가요?</b><br/>
        A. 중앙 운영자가 임의로 “사용자 대신 서명”하기 어려워져(서명 권한이 중앙에 모이지 않음) 내부자 남용 공격면이 줄어듭니다.
        대신 멀티기기/분실 복구(KMC/KYC) 정책을 함께 가져가야 운영이 가능합니다.
      </div>
      <div class="muted" style="margin-top: 10px;">
        <b>Q. “IndexedDB의 non-extractable CryptoKey”를 쉽게 말하면?</b><br/>
        A. private key를 “문자열/파일로 뽑아가기(export)”는 막고, “서명 연산만 요청(sign)” 가능하게 브라우저 안에 가둔 키 핸들을
        IndexedDB에 저장해서 같은 origin에서 재사용하는 방식입니다.
      </div>
    </details>
  </div>
  <div class="grid">
    <div class="card">
      <h2>✅ User (Login + Enroll)</h2>
      <div class="row muted" id="session_status">Checking session...</div>
      <div class="row">
        <label>Email</label><br/>
        <input id="email" type="email" placeholder="user@example.com" />
      </div>
      <div class="row">
        <button id="btn_passkey" onclick="loginWebAuthn()">Login with Passkey</button>
        <button id="btn_google" onclick="loginGoogle()">Login with Google</button>
        <button id="btn_logout" onclick="logout()" style="display:none">Logout</button>
      </div>
      <div class="row">
        <button id="btn_setup_passkey" onclick="setupPasskey()" style="display:none">Set up Passkey</button>
        <div class="muted" id="setup_passkey_hint" style="display:none">
          Required for step-up gated DPoP key enrollment.
        </div>
      </div>

      <hr/>
      <h3>DPoP Key Enrollment (step-up gated)</h3>
      <div class="row">
        <label>member_id (optional)</label><br/>
        <input id="member_id" type="text" placeholder="member123" />
      </div>
      <div class="row">
        <button onclick="enrollDPoP()">Generate & Register DPoP Key</button>
        <div class="muted">
          Tip: enroll twice to get two different keys. The previous token is saved as <code>prev_access_token</code> and the previous key is stored in the <code>prev</code> slot.
        </div>
      </div>

      <h3>Key storage (safe-by-design)</h3>
      <div class="muted">
        The DPoP <b>private</b> key is stored as a <b>non-extractable</b> <code>CryptoKey</code> in <b>IndexedDB</b>.
        JavaScript can hold a handle to the key for signing, but cannot export it as JWK/bytes.
        (Legacy sites cannot access this key due to origin isolation; only the DPoP agent origin can.)
      </div>
      <details style="margin-top: 10px;">
        <summary>쉽게 설명: “IndexedDB의 non-extractable CryptoKey”가 뭐야?</summary>
        <div class="muted" style="margin-top: 10px;">
          <b>CryptoKey</b>는 브라우저가 관리하는 “키 객체 핸들(handle)”입니다. 비유하면 “금고 열쇠의 실물”이 아니라,
          <b>금고 안에 있는 열쇠를 쓰게 해주는 손잡이</b> 같은 거예요.
        </div>
        <div class="muted" style="margin-top: 8px;">
          <b>non-extractable</b>은 이 핸들로는 <b>키 재료(예: JWK의 private <code>d</code>)를 밖으로 꺼내는(export) 기능이 금지</b>된 상태를 뜻합니다.
          즉 JS가 <code>sign()</code> 같은 연산은 요청할 수 있어도, private key를 “문자열/파일”로 뽑아가기는 어렵게 만듭니다.
        </div>
        <div class="muted" style="margin-top: 8px;">
          그리고 이 핸들은 <b>IndexedDB</b>에 저장할 수 있어서, 같은 origin(dpop.skplanet.com)에서 다시 열어도 키를 재사용할 수 있습니다.
        </div>
        <div class="muted" style="margin-top: 8px;">
          <b>중요한 주의점</b>: non-extractable이 “악성 스크립트가 서명을 못 한다”는 뜻은 아닙니다.
          만약 DPoP Agent origin에서 XSS가 발생하면, 공격자는 키를 “export”하진 못해도 그 페이지 컨텍스트에서 서명 API를 호출해 악용할 수 있습니다.
          그래서 CSP/입력검증/권한분리 같은 웹 보안이 여전히 중요합니다.
        </div>
      </details>
      <div class="row">
        <button onclick="showKeyStorage()">Show key storage details</button>
        <button onclick="provePrivateKeyNonExtractable()">Prove: cannot export private JWK</button>
      </div>
      <pre id="key_storage_out"></pre>

      <h3>Status</h3>
      <pre id="out"></pre>
    </div>

    <div class="card">
      <h2>🕵️ Attacker scenarios (A/B/C/D/E)</h2>
      <div class="muted">
        This panel helps you reproduce failure modes locally. Results are logged below with timestamps.
      </div>

      <div class="row">
        <div class="muted">
          Tokens used by scenarios:
          <code>access_token</code> (current) and <code>prev_access_token</code> (simulated “stolen token”, saved on enroll).
        </div>
      </div>

      <details style="margin-top: 10px;">
        <summary>시나리오 설명(일반인용)</summary>
        <div class="muted" style="margin-top: 10px;">
          이 버튼들은 “DPoP가 뭘 막아주는지”를 눈으로 확인하기 위한 데모입니다.
        </div>
        <ul class="muted" style="margin-top: 10px;">
          <li><b>Attack A</b>: 토큰만 들고 API 호출(증명 없음) → 서버가 “증명 없음”으로 차단</li>
          <li><b>Attack B</b>: 훔친 토큰(prev_access_token) + 다른 키로 증명 생성 → “토큰에 묶인 키와 불일치/미등록”으로 차단</li>
          <li><b>Attack C</b>: (테스트 가정) 서버 시크릿을 안다고 치고 토큰을 위조 + 미등록 키 → 등록/검증 게이트로 차단</li>
          <li><b>Attack D</b>: 같은 DPoP proof(JTI)를 그대로 2번 재전송 → 2번째는 <code>REPLAY</code>로 차단(재사용 방지)</li>
          <li><b>Attack E</b>: “Agent origin이 뚫린(XSS 등) 상황” 시뮬레이션 → 키를 export 못 해도 <code>sign()</code>을 악용해 요청을 보낼 수 있음(위협모델 경고)</li>
        </ul>
      </details>

      <div class="row">
        <label>member_id</label><br/>
        <input id="atk_member_id" type="text" value="member123" />
      </div>

      <div class="row">
        <button onclick="attackTokenOnly()">Attack A: token only (no DPoP)</button>
        <button onclick="attackStolenTokenWrongKey()">Attack B: stolen token + wrong key proof (expect reject)</button>
        <button onclick="attackReplaySameProofTwice()">Attack D: replay same proof twice</button>
        <button onclick="clearAttackLog()">Clear attack log</button>
      </div>
      <div class="muted">
        Expected:
        Attack A → <code>PROOF_MISSING</code>.
        Attack B → <code>UNREGISTERED_KEY</code> or <code>TOKEN_PROOF_JKT_MISMATCH</code>.
        Attack D → first ok, second <code>REPLAY</code>.
      </div>

      <hr/>
      <h3>Scenario C (test only): forge access_token using server secret</h3>
      <div class="muted">
        For demo purposes, you can paste a <b>test</b> <code>ACCESS_TOKEN_SECRET</code> here and forge a token bound to an unregistered key.
        Do NOT do this in production.
      </div>
      <div class="row">
        <label>ACCESS_TOKEN_SECRET (test)</label><br/>
        <input id="atk_secret" type="text" value="dev-only-change-me" />
      </div>
      <div class="row">
        <button onclick="attackForgedTokenUnregisteredKey()">Attack C: forged token + unregistered key proof</button>
      </div>

      <hr/>
      <h3>Attack E (security note): if this origin is compromised (XSS)</h3>
      <div class="muted">
        This is a <b>threat-model demo</b>. non-extractable means “can’t export the key”, not “can’t misuse sign()”.
      </div>
      <div class="row">
        <button onclick="attackAgentOriginCompromised()">Attack E: simulate malicious JS calling sign()</button>
      </div>

      <h3>Attack result</h3>
      <pre id="atk_out"></pre>
    </div>
  </div>
  <script>
    const out = document.getElementById('out');
    const atkOut = document.getElementById('atk_out');
    const keyStorageOut = document.getElementById('key_storage_out');
    function log(obj) { out.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2); }
    function logAtkEvent(title, obj) {
      const ts = new Date().toLocaleTimeString();
      const body = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
      const entry = '[' + ts + '] ' + title + '\\n' + body + '\\n';
      atkOut.textContent = entry + '\\n' + atkOut.textContent;
    }
    function logKeyStorage(obj) {
      keyStorageOut.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
    }

    function clearAttackLog() {
      atkOut.textContent = '';
    }

    function base64urlToUint8Array(base64url) {
      const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
      const pad = base64.length % 4 ? '='.repeat(4 - (base64.length % 4)) : '';
      const bin = atob(base64 + pad);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    }
    function uint8ArrayToBase64url(bytes) {
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, '');
    }

    function jsonToBase64url(obj) {
      const s = JSON.stringify(obj);
      return uint8ArrayToBase64url(new TextEncoder().encode(s));
    }

    async function sha256(bytes) {
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      return new Uint8Array(digest);
    }

    async function jwkThumbprintP256(jwk) {
      // RFC7638 thumbprint for EC key: JSON with members in lexicographic order
      const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      const hash = await sha256(new TextEncoder().encode(canonical));
      return uint8ArrayToBase64url(hash);
    }

    function decodeJwtPayloadNoVerify(jwt) {
      try {
        const parts = jwt.split('.');
        if (parts.length < 2) return null;
        const payloadJson = new TextDecoder().decode(base64urlToUint8Array(parts[1]));
        return JSON.parse(payloadJson);
      } catch {
        return null;
      }
    }

    // --- IndexedDB key storage (non-extractable private key) ---
    async function openKeyDb() {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open('dpop-demo', 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains('keys')) db.createObjectStore('keys');
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }

    async function idbGet(store, key) {
      const db = await openKeyDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readonly');
        const st = tx.objectStore(store);
        const req = st.get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }

    async function idbPut(store, key, value) {
      const db = await openKeyDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(store, 'readwrite');
        const st = tx.objectStore(store);
        const req = st.put(value, key);
        req.onsuccess = () => resolve(true);
        req.onerror = () => reject(req.error);
      });
    }

    async function getStoredKey(slot) {
      return await idbGet('keys', slot);
    }

    async function setStoredKey(slot, value) {
      await idbPut('keys', slot, value);
    }

    async function provePrivateKeyNonExtractable() {
      const obj = await getStoredKey('current');
      if (!obj) return logKeyStorage({ error: 'no_enrolled_key', hint: 'Enroll first.' });
      try {
        // This should fail because privateKey is non-extractable
        const jwk = await crypto.subtle.exportKey('jwk', obj.privateKey);
        logKeyStorage({ unexpected: true, exported_private_jwk: jwk });
      } catch (e) {
        logKeyStorage({ expected_failure: true, name: e?.name, message: String(e) });
      }
    }

    async function showKeyStorage() {
      const obj = await getStoredKey('current');
      if (!obj) return logKeyStorage({ has_key: false, note: 'No enrolled key found. Enroll first.' });
      const { privateKey, publicJwk, createdAt } = obj;
      logKeyStorage({
        has_key: true,
        storage: { type: 'IndexedDB', db: 'dpop-demo', store: 'keys', key: 'current' },
        createdAt,
        privateKey: {
          type: privateKey?.type,
          extractable: privateKey?.extractable,
          algorithm: privateKey?.algorithm,
          usages: privateKey?.usages,
        },
        publicJwk,
      });
    }

    async function signHs256Jwt(payload, secret) {
      const header = { alg: 'HS256', typ: 'JWT' };
      const encHeader = jsonToBase64url(header);
      const encPayload = jsonToBase64url(payload);
      const signingInput = encHeader + '.' + encPayload;
      const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(signingInput));
      const encSig = uint8ArrayToBase64url(new Uint8Array(sig));
      return signingInput + '.' + encSig;
    }

    function decodeCreationOptionsFromJSON(opts) {
      opts.challenge = base64urlToUint8Array(opts.challenge);
      opts.user.id = base64urlToUint8Array(opts.user.id);
      if (opts.excludeCredentials) {
        opts.excludeCredentials = opts.excludeCredentials.map(c => ({ ...c, id: base64urlToUint8Array(c.id) }));
      }
      return opts;
    }
    function decodeRequestOptionsFromJSON(opts) {
      opts.challenge = base64urlToUint8Array(opts.challenge);
      if (opts.allowCredentials) {
        opts.allowCredentials = opts.allowCredentials.map(c => ({ ...c, id: base64urlToUint8Array(c.id) }));
      }
      return opts;
    }

    function derToJoseEcdsa(sig, size) {
      // Accept both formats:
      // - raw (r||s) signature length == size*2 (some WebCrypto impls)
      // - ASN.1 DER ECDSA signature (SEQUENCE{ r INTEGER, s INTEGER })
      // Return raw jose signature (r||s), size*2 bytes.
      const bytes = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
      if (bytes.length === size * 2) return bytes; // already jose/raw
      let i = 0;
      if (bytes[i++] !== 0x30) throw new Error('Bad DER (seq)');
      const seqLen = bytes[i++];
      if (seqLen & 0x80) { // long form not expected here
        const n = seqLen & 0x7f;
        i += n;
      }
      if (bytes[i++] !== 0x02) throw new Error('Bad DER (int r)');
      let rLen = bytes[i++];
      let r = bytes.slice(i, i + rLen); i += rLen;
      if (bytes[i++] !== 0x02) throw new Error('Bad DER (int s)');
      let sLen = bytes[i++];
      let s = bytes.slice(i, i + sLen); i += sLen;

      // Remove leading zeros, then left pad to size
      while (r.length > 0 && r[0] === 0x00) r = r.slice(1);
      while (s.length > 0 && s[0] === 0x00) s = s.slice(1);
      if (r.length > size || s.length > size) throw new Error('Bad DER (size)');

      const out = new Uint8Array(size * 2);
      out.set(r, size - r.length);
      out.set(s, size * 2 - s.length);
      return out;
    }

    async function createDpopJwtFromKeyRef(keyRef, htm, htu) {
      const now = Math.floor(Date.now() / 1000);
      const jti = crypto.randomUUID();
      const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: keyRef.publicJwk };
      const payload = { htm: htm, htu: htu, iat: now, jti: jti };
      const encHeader = jsonToBase64url(header);
      const encPayload = jsonToBase64url(payload);
      const signingInput = encHeader + '.' + encPayload;

      const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyRef.privateKey, new TextEncoder().encode(signingInput));
      const rawSig = derToJoseEcdsa(new Uint8Array(sigBuf), 32);
      const encSig = uint8ArrayToBase64url(rawSig);
      return signingInput + '.' + encSig;
    }

    function registrationCredentialToJSON(cred) {
      return {
        id: cred.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(cred.rawId)),
        type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(cred.response.clientDataJSON)),
          attestationObject: uint8ArrayToBase64url(new Uint8Array(cred.response.attestationObject)),
          transports: cred.response.getTransports ? cred.response.getTransports() : [],
        },
      };
    }

    function authenticationCredentialToJSON(cred) {
      return {
        id: cred.id,
        rawId: uint8ArrayToBase64url(new Uint8Array(cred.rawId)),
        type: cred.type,
        authenticatorAttachment: cred.authenticatorAttachment,
        clientExtensionResults: cred.getClientExtensionResults(),
        response: {
          clientDataJSON: uint8ArrayToBase64url(new Uint8Array(cred.response.clientDataJSON)),
          authenticatorData: uint8ArrayToBase64url(new Uint8Array(cred.response.authenticatorData)),
          signature: uint8ArrayToBase64url(new Uint8Array(cred.response.signature)),
          userHandle: cred.response.userHandle ? uint8ArrayToBase64url(new Uint8Array(cred.response.userHandle)) : undefined,
        },
      };
    }

    async function loginWebAuthn() {
      const email = document.getElementById('email').value;
      if (!email) return log('email required');

      const { mode, options } = await fetch('/v1/auth/webauthn/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      }).then(r => r.json());

      if (mode === 'registration') {
        const publicKey = decodeCreationOptionsFromJSON(options);
        const cred = await navigator.credentials.create({ publicKey });
        const credential = registrationCredentialToJSON(cred);
        const resp = await fetch('/v1/auth/webauthn/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, mode, credential })
        }).then(r => r.json());
        log(resp);
        await refreshSessionUI();
        return;
      }

      const publicKey = decodeRequestOptionsFromJSON(options);
      const cred = await navigator.credentials.get({ publicKey });
      const credential = authenticationCredentialToJSON(cred);
      const resp = await fetch('/v1/auth/webauthn/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, mode, credential })
      }).then(r => r.json());
      log(resp);
      await refreshSessionUI();
    }

    function loginGoogle() {
      window.location.href = '/v1/auth/google/start';
    }

    async function logout() {
      await fetch('/v1/logout', { method: 'POST' });
      localStorage.removeItem('access_token');
      localStorage.removeItem('prev_access_token');
      // keep IndexedDB keys for demo unless you want to wipe them
      await refreshSessionUI();
      log('Logged out');
    }

    async function refreshSessionUI() {
      const el = document.getElementById('session_status');
      const passkeyBtn = document.getElementById('btn_passkey');
      const googleBtn = document.getElementById('btn_google');
      const logoutBtn = document.getElementById('btn_logout');
      const setupBtn = document.getElementById('btn_setup_passkey');
      const setupHint = document.getElementById('setup_passkey_hint');
      const emailInput = document.getElementById('email');

      const me = await fetch('/v1/me').then(r => r.json()).catch(() => ({ logged_in: false }));
      if (me.logged_in) {
        el.textContent = 'Logged in as ' + me.user.email;
        if (emailInput && !emailInput.value) emailInput.value = me.user.email;
        passkeyBtn.style.display = 'none';
        googleBtn.style.display = 'none';
        logoutBtn.style.display = 'inline-block';
        if (me.has_passkey) {
          setupBtn.style.display = 'none';
          setupHint.style.display = 'none';
        } else {
          setupBtn.style.display = 'inline-block';
          setupHint.style.display = 'block';
        }
      } else {
        el.textContent = 'Not logged in';
        passkeyBtn.style.display = 'inline-block';
        googleBtn.style.display = 'inline-block';
        logoutBtn.style.display = 'none';
        setupBtn.style.display = 'none';
        setupHint.style.display = 'none';
      }
    }
    async function setupPasskey() {
      const me = await fetch('/v1/me').then(r => r.json()).catch(() => ({ logged_in: false }));
      if (!me.logged_in) return log({ error: 'login_required' });
      if (me.has_passkey) return log({ success: true, note: 'passkey already registered' });

      const opts = await fetch('/v1/auth/webauthn/enroll/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      }).then(async r => {
        const t = await r.text();
        try { return JSON.parse(t); } catch { throw new Error(t); }
      });
      if (opts.error) return log(opts);

      const publicKey = decodeCreationOptionsFromJSON(opts.options);
      const cred = await navigator.credentials.create({ publicKey });
      const credential = registrationCredentialToJSON(cred);
      const resp = await fetch('/v1/auth/webauthn/enroll/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential })
      }).then(r => r.json());
      log(resp);
      await refreshSessionUI();
      return resp;
    }

    // Initialize session UI on load
    refreshSessionUI();

    function getTokenFromStorage(key) {
      const v = localStorage.getItem(key);
      return (v && v.trim()) ? v.trim() : '';
    }

    async function attackTokenOnly() {
      const token = getTokenFromStorage('access_token');
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!token) return logAtkEvent('Attack A', 'access_token missing. Login + enroll first.');

      logAtkEvent('Attack A → request', { has_token: true, has_dpop: false, member_id });
      const resp = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token },
        body: JSON.stringify({ member_id, payload: { demo: 'attack-token-only', ts: new Date().toISOString() } })
      }).then(r => r.json());
      logAtkEvent('Attack A → response', resp);
    }

    async function attackTokenWithProof(token, keyRef, label) {
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!token) return logAtkEvent(label, 'access_token required');

      const tokenPayload = decodeJwtPayloadNoVerify(token);
      const tokenJkt = tokenPayload?.cnf?.jkt;
      const keyJkt = await jwkThumbprintP256(keyRef.publicJwk);
      const match = (typeof tokenJkt === 'string') ? (tokenJkt === keyJkt) : null;

      const htu = window.location.origin + '/v1/ingest/event';
      let dpop;
      try {
        dpop = await createDpopJwtFromKeyRef(keyRef, 'POST', htu);
      } catch (e) {
        return logAtkEvent(label + ' → error', String(e));
      }

      logAtkEvent(label + ' → request', { member_id, token_jkt: tokenJkt ?? null, key_jkt: keyJkt, jkt_match: match });
      const resp = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify({ member_id, payload: { demo: 'attack-token-with-proof', ts: new Date().toISOString() } })
      }).then(r => r.json());
      logAtkEvent(match === true ? (label + ' → response (VALID pair, expect ALLOW)') : (label + ' → response (MISMATCH/ATTACK, expect reject)'), resp);
    }

    async function attackStolenTokenWrongKey() {
      const token = getTokenFromStorage('prev_access_token');
      if (!token) return logAtkEvent('Attack B', 'prev_access_token missing. Enroll twice (or enroll once after you already have an access_token).');

      // generate a fresh unregistered attacker key each time (guaranteed "wrong key")
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
      const keyRef = { privateKey: kp.privateKey, publicJwk };

      await attackTokenWithProof(token, keyRef, 'Attack B (stolen prev token + wrong key proof)');
    }

    async function attackReplaySameProofTwice() {
      const token = getTokenFromStorage('access_token');
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!token) return logAtkEvent('Attack D', 'access_token missing. Login + enroll first.');

      const enrolled = await getStoredKey('current');
      if (!enrolled) return logAtkEvent('Attack D', 'No enrolled key found. Enroll first.');

      const htu = window.location.origin + '/v1/ingest/event';
      const keyRef = { privateKey: enrolled.privateKey, publicJwk: enrolled.publicJwk };
      const dpop = await createDpopJwtFromKeyRef(keyRef, 'POST', htu);

      const body = { member_id, payload: { demo: 'attack-replay-proof', ts: new Date().toISOString() } };
      logAtkEvent('Attack D → request #1', { member_id, note: 'same proof will be reused', expect: 'ALLOW/OK' });
      const resp1 = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify(body),
      }).then(r => r.json());
      logAtkEvent('Attack D → response #1', resp1);

      logAtkEvent('Attack D → request #2 (replay)', { member_id, expect: 'REPLAY (blocked)' });
      const resp2 = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify(body),
      }).then(r => r.json());
      logAtkEvent('Attack D → response #2 (expect REPLAY)', resp2);
    }

    async function attackAgentOriginCompromised() {
      const token = getTokenFromStorage('access_token');
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!token) return logAtkEvent('Attack E', 'access_token missing. Login + enroll first.');

      const enrolled = await getStoredKey('current');
      if (!enrolled) return logAtkEvent('Attack E', 'No enrolled key found. Enroll first.');

      const htu = window.location.origin + '/v1/ingest/event';
      const keyRef = { privateKey: enrolled.privateKey, publicJwk: enrolled.publicJwk };
      const dpop = await createDpopJwtFromKeyRef(keyRef, 'POST', htu);

      logAtkEvent('Attack E → request (threat model)', {
        note: 'Simulates malicious JS running on the DPoP origin calling sign() with the enrolled key handle (key is still non-extractable).',
        member_id,
      });
      const resp = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify({ member_id, payload: { demo: 'attack-agent-origin-compromised', ts: new Date().toISOString() } }),
      }).then(r => r.json());

      logAtkEvent('Attack E → response (may ALLOW; shows XSS risk)', resp);
    }

    async function attackForgedTokenUnregisteredKey() {
      const secret = document.getElementById('atk_secret').value.trim();
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!secret) return logAtkEvent('Attack C', 'ACCESS_TOKEN_SECRET required (test-only)');

      // generate an unregistered attacker key
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
      const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

      const jkt = await jwkThumbprintP256(publicJwk);
      const now = Math.floor(Date.now() / 1000);

      // forge access token (same claims our server expects)
      const token = await signHs256Jwt(
        { cnf: { jkt }, iss: 'dpop-login-fds', aud: 'ingest', sub: 'attacker', iat: now, exp: now + 600 },
        secret
      );

      const htu = window.location.origin + '/v1/ingest/event';
      let dpop;
      try {
        const keyRef = { privateKey: keyPair.privateKey, publicJwk };
        dpop = await createDpopJwtFromKeyRef(keyRef, 'POST', htu);
      } catch (e) {
        return logAtkEvent('Attack C → error', String(e));
      }

      logAtkEvent('Attack C → request', { forged_jkt: jkt, has_token: true, has_dpop: true, member_id });
      const resp = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify({ member_id, payload: { demo: 'attack-forged-token-unregistered-key', ts: new Date().toISOString() } })
      }).then(r => r.json());

      logAtkEvent('Attack C → response', { forged_jkt: jkt, response: resp });
    }

    async function enrollDPoP() {
      const member_id = document.getElementById('member_id').value || undefined;

      // Ensure passkey exists for step-up gated enrollment
      const me = await fetch('/v1/me').then(r => r.json()).catch(() => ({ logged_in: false }));
      if (!me.logged_in) return log({ error: 'login_required' });
      if (!me.has_passkey) {
        const r = await setupPasskey();
        // refreshSessionUI already called
        const me2 = await fetch('/v1/me').then(r => r.json()).catch(() => ({ logged_in: false }));
        if (!me2.logged_in || !me2.has_passkey) return; // setup failed or cancelled
      }

      // Start an enrollment (server-side 1-time challenge + TTL)
      const enroll = await fetch('/v1/dpop/enroll/start', { method: 'POST' }).then(async r => {
        const t = await r.text();
        try { return JSON.parse(t); } catch { throw new Error(t); }
      });
      if (enroll.error) return log(enroll);

      // Step-up with passkey (user verification required)
      let stepupOpts = await fetch('/v1/auth/webauthn/stepup/options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enrollment_id: enroll.enrollment_id })
      }).then(async r => {
        const t = await r.text();
        try { return JSON.parse(t); } catch { throw new Error(t); }
      });
      if (stepupOpts?.error === 'no_passkey_registered') {
        await setupPasskey();
        stepupOpts = await fetch('/v1/auth/webauthn/stepup/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enrollment_id: enroll.enrollment_id })
        }).then(r => r.json());
      }
      if (stepupOpts.error) return log(stepupOpts);

      const stepupPublicKey = decodeRequestOptionsFromJSON(stepupOpts.options);
      const assertion = await navigator.credentials.get({ publicKey: stepupPublicKey });
      const stepupCredential = authenticationCredentialToJSON(assertion);
      const stepupVerify = await fetch('/v1/auth/webauthn/stepup/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enrollment_id: enroll.enrollment_id, credential: stepupCredential })
      }).then(r => r.json());
      if (!stepupVerify.success) return log(stepupVerify);

      // Create keypair and persist private key as a non-extractable CryptoKey in IndexedDB.
      // We generate an extractable keypair, export JWKs, then re-import the private key as non-extractable.
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
      const privateJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
      const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
      await setStoredKey('current', { privateKey, publicJwk, createdAt: new Date().toISOString() });
      await showKeyStorage();

      // Proof-of-possession: sign the server enrollment challenge with private key
      const msg = new TextEncoder().encode('dpop-enroll:' + enroll.enrollment_id + ':' + enroll.challenge);
      const sigBuf = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, msg);
      const signature = uint8ArrayToBase64url(new Uint8Array(sigBuf));

      const resp = await fetch('/v1/dpop/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jwk: publicJwk, member_id, enrollment_id: enroll.enrollment_id, proof: { signature } })
      }).then(r => r.json());

      // Demo storage only (do NOT do this in production)
      // Keep the previous values so we can demo "stolen token used with different key" scenarios.
      const prevToken = localStorage.getItem('access_token');
      if (prevToken) localStorage.setItem('prev_access_token', prevToken);
      if (resp && resp.access_token) {
        localStorage.setItem('access_token', resp.access_token);
      }
      log(resp);
    }
  </script>
</body>
</html>
  `;
}