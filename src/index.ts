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
import { verifyIngestAccessToken } from './token';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

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
    if (path === '/v1/export/canonical' && request.method === 'GET') {
      return handleExportCanonical(request, env.DB);
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

  const verification = await verifyDPoP(dpopHeader, request.method, request.url, db);
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
    htu: request.url,
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
  </style>
</head>
<body>
  <h1>DPoP Demo</h1>
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

      <h3>Status</h3>
      <pre id="out"></pre>
    </div>

    <div class="card">
      <h2>🕵️ Attacker (Try to use stolen token / wrong key)</h2>
      <div class="muted">
        This panel helps you reproduce failure modes locally. Results are logged below with timestamps.
      </div>

      <div class="row">
        <label>Authorization token (access_token)</label><br/>
        <textarea id="atk_token" rows="3" placeholder="eyJ..."></textarea>
        <div class="row">
          <button onclick="loadToken('access_token')">Load current token</button>
          <button onclick="clearField('atk_token')">Clear</button>
        </div>
      </div>

      <div class="row">
        <label>DPoP signing key (non-extractable)</label><br/>
        <div class="muted">
          Private key is stored as a <code>CryptoKey</code> in IndexedDB (non-extractable). It is not displayed/exported as JWK.
        </div>
        <div class="row">
          <button onclick="generateUnregisteredAttackKey()">Generate unregistered attacker key</button>
          <button onclick="tryExportEnrolledPrivateJwk()">Prove: cannot export private JWK</button>
        </div>
      </div>

      <div class="row">
        <label>member_id</label><br/>
        <input id="atk_member_id" type="text" value="member123" />
      </div>

      <div class="row">
        <button onclick="attackTokenOnly()">Attack A: token only (no DPoP)</button>
        <button onclick="attackTokenWithProof()">Send token + proof (will ALLOW if it matches)</button>
        <button onclick="clearAttackLog()">Clear attack log</button>
      </div>
      <div class="muted">
        Expected: token-only → <code>PROOF_MISSING</code>. token+proof with wrong key → <code>UNREGISTERED_KEY</code> or <code>TOKEN_PROOF_JKT_MISMATCH</code>.
        <br/>Note: "wrong key" means the signing key does <b>not</b> correspond to the token's <code>cnf.jkt</code> (use mismatch or generate an unregistered key).
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

      <h3>Attack result</h3>
      <pre id="atk_out"></pre>
    </div>
  </div>
  <script>
    const out = document.getElementById('out');
    const atkOut = document.getElementById('atk_out');
    function log(obj) { out.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2); }
    function logAtkEvent(title, obj) {
      const ts = new Date().toLocaleTimeString();
      const body = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
      const entry = '[' + ts + '] ' + title + '\\n' + body + '\\n';
      atkOut.textContent = entry + '\\n' + atkOut.textContent;
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

    let selectedAttackKey = null; // { privateKey, publicJwk }

    async function tryExportEnrolledPrivateJwk() {
      const obj = await getStoredKey('current');
      if (!obj) return logAtkEvent('Export private JWK', 'No enrolled key found. Enroll first.');
      try {
        // This should fail because privateKey is non-extractable
        const jwk = await crypto.subtle.exportKey('jwk', obj.privateKey);
        logAtkEvent('Export private JWK (UNEXPECTED SUCCESS)', jwk);
      } catch (e) {
        logAtkEvent('Export private JWK (expected failure)', { name: e?.name, message: String(e) });
      }
    }

    async function generateUnregisteredAttackKey() {
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
      selectedAttackKey = { privateKey: kp.privateKey, publicJwk };
      const jkt = await jwkThumbprintP256(publicJwk);
      logAtkEvent('Generate unregistered key', { jkt });
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

    function loadToken(key) {
      const v = localStorage.getItem(key);
      document.getElementById('atk_token').value = v || '';
      logAtkEvent('Load token', { loaded: key, length: v ? v.length : 0 });
    }
    function clearField(id) {
      document.getElementById(id).value = '';
    }

    async function attackTokenOnly() {
      const token = document.getElementById('atk_token').value.trim();
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!token) return logAtkEvent('Attack A', 'access_token required');

      logAtkEvent('Attack A → request', { has_token: true, has_dpop: false, member_id });
      const resp = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token },
        body: JSON.stringify({ member_id, payload: { demo: 'attack-token-only', ts: new Date().toISOString() } })
      }).then(r => r.json());
      logAtkEvent('Attack A → response', resp);
    }

    async function attackTokenWithProof() {
      const token = document.getElementById('atk_token').value.trim();
      const member_id = document.getElementById('atk_member_id').value.trim() || 'member123';
      if (!token) return logAtkEvent('Attack B', 'access_token required');

      if (!selectedAttackKey) return logAtkEvent('Attack B', 'Generate an unregistered attacker key first.');
      const keyRef = selectedAttackKey;

      const tokenPayload = decodeJwtPayloadNoVerify(token);
      const tokenJkt = tokenPayload?.cnf?.jkt;
      const keyJkt = await jwkThumbprintP256(keyRef.publicJwk);
      const match = (typeof tokenJkt === 'string') ? (tokenJkt === keyJkt) : null;

      const htu = window.location.origin + '/v1/ingest/event';
      let dpop;
      try {
        dpop = await createDpopJwtFromKeyRef(keyRef, 'POST', htu);
      } catch (e) {
        return logAtkEvent('Attack B → error', String(e));
      }

      logAtkEvent('Send token + proof → request', { member_id, token_jkt: tokenJkt ?? null, key_jkt: keyJkt, jkt_match: match });
      const resp = await fetch('/v1/ingest/event', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'DPoP ' + token, 'DPoP': dpop },
        body: JSON.stringify({ member_id, payload: { demo: 'attack-token-with-proof', ts: new Date().toISOString() } })
      }).then(r => r.json());
      logAtkEvent(match === true ? 'Send token + proof → response (VALID pair, expect ALLOW)' : 'Send token + proof → response (MISMATCH/ATTACK, expect reject)', resp);
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