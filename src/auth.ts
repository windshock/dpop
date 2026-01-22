import type { JWK, JWTPayload } from 'jose';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/types';
import type { Env } from './env';
import { getCookie, json, readJson, setCookieHeader } from './http';
import { registerDPoPKey } from './dpop';
import { createSession, getSessionUser, isSecureRequest, sessionCookieName } from './session';
import { base64urlDecodeToUint8Array, base64urlEncode, randomBase64url, sha256Base64url } from './utils';
import type { User, WebAuthnCredentialRecord } from './types';
import { issueIngestAccessToken } from './token';

type WebAuthnOptionsReq = { email: string };
type WebAuthnVerifyReq = { email: string; mode: 'registration' | 'authentication'; credential: RegistrationResponseJSON | AuthenticationResponseJSON };
type WebAuthnStepUpOptionsReq = { enrollment_id: string };
type WebAuthnStepUpVerifyReq = { enrollment_id: string; credential: AuthenticationResponseJSON };
type WebAuthnEnrollVerifyReq = { credential: RegistrationResponseJSON };

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'] as const;
const WEBAUTHN_ALGS_ES256 = [-7] as const;

function googleRedirectUri(env: Env): string {
  // redirect_uri must be fixed, not derived from request.url (prevents dynamic redirects / proxy confusion)
  return new URL('/v1/auth/google/callback', env.ORIGIN).toString();
}

async function verifyGoogleIdToken(env: Env, idToken: string, expectedNonce: string): Promise<JWTPayload> {
  // Google JWKS
  const jwks = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  const { payload } = await jwtVerify(idToken, jwks, {
    audience: env.GOOGLE_CLIENT_ID,
    issuer: GOOGLE_ISSUERS as unknown as string[],
  });

  // Optional-but-recommended: iat sanity window
  if (typeof payload.iat === 'number') {
    const now = Math.floor(Date.now() / 1000);
    if (payload.iat > now + 60) throw new Error('id_token iat in future');
    if (payload.iat < now - 10 * 60) throw new Error('id_token too old');
  }

  if (expectedNonce) {
    if (typeof payload.nonce !== 'string' || payload.nonce !== expectedNonce) {
      throw new Error('id_token nonce mismatch');
    }
  }
  return payload;
}

function extractClientChallenge(credential: RegistrationResponseJSON | AuthenticationResponseJSON): string | null {
  try {
    const json = new TextDecoder().decode(base64urlDecodeToUint8Array(credential.response.clientDataJSON));
    const data = JSON.parse(json) as { challenge?: unknown };
    return typeof data.challenge === 'string' ? data.challenge : null;
  } catch {
    return null;
  }
}

export async function handleWebAuthnOptions(request: Request, env: Env): Promise<Response> {
  const body = await readJson<WebAuthnOptionsReq>(request);
  if (!body.email) return json({ error: 'email required' }, { status: 400 });

  const email = normalizeEmail(body.email);
  let user = (await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first()) as User | null;

  // Load existing credentials (if any)
  const creds = user
    ? (((await env.DB.prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?').bind(user.id).all()).results ?? []) as unknown as WebAuthnCredentialRecord[])
    : [];

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const createdAt = new Date().toISOString();

  if (!user || creds.length === 0) {
    // Create user record if needed (so we have stable userID)
    if (!user) {
      user = { id: crypto.randomUUID(), email, created_at: createdAt };
      await env.DB.prepare('INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)').bind(user.id, user.email, user.created_at).run();
    }

    const options = await generateRegistrationOptions({
      rpName: env.WEBAUTHN_RP_NAME,
      rpID: env.RP_ID,
      userID: new TextEncoder().encode(user.id),
      userName: user.email,
      timeout: 60_000,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      supportedAlgorithmIDs: [...WEBAUTHN_ALGS_ES256],
      excludeCredentials: creds.map((c) => ({ id: c.credential_id })),
    });

    await env.DB
      .prepare('INSERT INTO webauthn_challenges (id, type, challenge, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), 'registration', options.challenge, user.id, email, createdAt, expiresAt)
      .run();

    return json({ mode: 'registration', options }, { status: 200 });
  }

  const options = await generateAuthenticationOptions({
    rpID: env.RP_ID,
    timeout: 60_000,
    userVerification: 'required',
    allowCredentials: creds.map((c) => ({ id: c.credential_id })),
  });

  await env.DB
    .prepare('INSERT INTO webauthn_challenges (id, type, challenge, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), 'authentication', options.challenge, user.id, email, createdAt, expiresAt)
    .run();

  return json({ mode: 'authentication', options }, { status: 200 });
}

export async function handleWebAuthnVerify(request: Request, env: Env): Promise<Response> {
  const body = await readJson<WebAuthnVerifyReq>(request);
  const email = body.email ? normalizeEmail(body.email) : '';
  if (!email || !body.mode || !body.credential) return json({ error: 'invalid request' }, { status: 400 });

  const user = (await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first()) as User | null;
  if (!user) return json({ error: 'unknown user' }, { status: 401 });

  const clientChallenge = extractClientChallenge(body.credential);
  if (!clientChallenge) return json({ error: 'missing client challenge' }, { status: 400 });

  const challengeRow = (await env.DB
    .prepare(
      `SELECT * FROM webauthn_challenges
       WHERE email = ? AND type = ? AND challenge = ?
       AND strftime('%s', expires_at) > strftime('%s', 'now')
       ORDER BY created_at DESC LIMIT 1`,
    )
    .bind(email, body.mode, clientChallenge)
    .first()) as { id: string; challenge: string } | null;

  if (!challengeRow) return json({ error: 'challenge not found or expired' }, { status: 400 });

  if (body.mode === 'registration') {
    let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
    try {
      verification = await verifyRegistrationResponse({
        response: body.credential as RegistrationResponseJSON,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin: env.ORIGIN,
        expectedRPID: env.RP_ID,
        supportedAlgorithmIDs: [...WEBAUTHN_ALGS_ES256],
      });
    } catch (e) {
      return json({ error: 'webauthn verify error', detail: String(e) }, { status: 400 });
    }

    if (!verification.verified || !verification.registrationInfo) return json({ error: 'webauthn verify failed' }, { status: 401 });

    const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

    try {
      await env.DB
        .prepare('INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .bind(
          crypto.randomUUID(),
          user.id,
          credentialID,
          base64urlEncode(credentialPublicKey),
          counter,
          JSON.stringify((body.credential as RegistrationResponseJSON).response.transports ?? []),
          new Date().toISOString(),
        )
        .run();
    } catch (e) {
      return json({ error: 'failed to store credential', detail: String(e) }, { status: 409 });
    }

    // Best-effort: consume challenge
    await env.DB.prepare('DELETE FROM webauthn_challenges WHERE id = ?').bind(challengeRow.id).run();

    const sessionId = await createSession(env.DB, user.id);
    const response = json({ success: true }, { status: 200 });
    response.headers.set(
      'Set-Cookie',
      setCookieHeader({
        name: sessionCookieName(),
        value: sessionId,
        httpOnly: true,
        sameSite: 'Lax',
        secure: isSecureRequest(request),
        maxAgeSeconds: 60 * 60 * 24,
      }),
    );
    return response;
  }

  // authentication
  const cred = body.credential as AuthenticationResponseJSON;
  const credRow = (await env.DB
    .prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?')
    .bind(cred.id, user.id)
    .first()) as WebAuthnCredentialRecord | null;
  if (!credRow) return json({ error: 'unknown credential' }, { status: 401 });

  const authenticator = {
    credentialID: credRow.credential_id,
    credentialPublicKey: base64urlDecodeToUint8Array(credRow.public_key),
    counter: credRow.counter,
    transports: (credRow.transports ? (JSON.parse(credRow.transports) as unknown[]) : []) as any,
  };

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: cred,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      authenticator,
      requireUserVerification: true,
    });
  } catch (e) {
    return json({ error: 'webauthn verify error', detail: String(e) }, { status: 400 });
  }

  if (!verification.verified || !verification.authenticationInfo) return json({ error: 'webauthn verify failed' }, { status: 401 });

  // signCount protection (best-effort): if both sides report >0 and it doesn't increase, treat as potential cloned credential.
  const newCounter = verification.authenticationInfo.newCounter;
  if (credRow.counter > 0 && newCounter > 0 && newCounter <= credRow.counter) {
    return json({ error: 'sign_count_replay_detected' }, { status: 409 });
  }

  await env.DB
    .prepare('UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?')
    .bind(newCounter, credRow.credential_id)
    .run();

  // Best-effort: consume challenge
  await env.DB.prepare('DELETE FROM webauthn_challenges WHERE id = ?').bind(challengeRow.id).run();

  const sessionId = await createSession(env.DB, user.id);
  const response = json({ success: true }, { status: 200 });
  response.headers.set(
    'Set-Cookie',
    setCookieHeader({
      name: sessionCookieName(),
      value: sessionId,
      httpOnly: true,
      sameSite: 'Lax',
      secure: isSecureRequest(request),
      maxAgeSeconds: 60 * 60 * 24,
    }),
  );
  return response;
}

export async function handleGoogleStart(request: Request, env: Env): Promise<Response> {
  // Encode nonce into state so we don't need a schema migration to store nonce separately.
  // base64url does not contain '.', so this split is safe.
  const nonce = randomBase64url(16);
  const state = `${randomBase64url(16)}.${nonce}`;
  const codeVerifier = randomBase64url(32);
  const codeChallenge = await sha256Base64url(codeVerifier);

  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await env.DB
    .prepare('INSERT INTO oauth_states (state, code_verifier, created_at, expires_at) VALUES (?, ?, ?, ?)')
    .bind(state, codeVerifier, createdAt, expiresAt)
    .run();

  const redirectUri = googleRedirectUri(env);
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', redirectUri);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('nonce', nonce);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  return Response.redirect(authUrl.toString(), 302);
}

export async function handleGoogleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code || !state) return json({ error: 'missing code/state' }, { status: 400 });

  const nonce = state.split('.', 2)[1] ?? '';

  const stateRow = (await env.DB
    .prepare(
      `SELECT * FROM oauth_states
       WHERE state = ?
       AND strftime('%s', expires_at) > strftime('%s', 'now')`,
    )
    .bind(state)
    .first()) as { code_verifier: string } | null;
  if (!stateRow) return json({ error: 'invalid state' }, { status: 400 });

  await env.DB.prepare('DELETE FROM oauth_states WHERE state = ?').bind(state).run();

  const redirectUri = googleRedirectUri(env);
  const form = new URLSearchParams();
  form.set('code', code);
  form.set('client_id', env.GOOGLE_CLIENT_ID);
  form.set('client_secret', env.GOOGLE_CLIENT_SECRET);
  form.set('redirect_uri', redirectUri);
  form.set('grant_type', 'authorization_code');
  form.set('code_verifier', stateRow.code_verifier);

  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  if (!tokenResp.ok) return json({ error: 'token exchange failed' }, { status: 401 });
  const token = (await tokenResp.json()) as { access_token?: string; id_token?: string };
  if (!token.id_token) return json({ error: 'missing id_token' }, { status: 401 });

  let idPayload: JWTPayload;
  try {
    idPayload = await verifyGoogleIdToken(env, token.id_token, nonce);
  } catch (e) {
    return json({ error: 'invalid id_token', detail: String(e) }, { status: 401 });
  }

  const sub = typeof idPayload.sub === 'string' ? idPayload.sub : '';
  const emailRaw = typeof idPayload.email === 'string' ? idPayload.email : '';
  const emailVerified = idPayload.email_verified === true;
  if (!sub) return json({ error: 'id_token missing sub' }, { status: 401 });
  if (!emailRaw) return json({ error: 'id_token missing email' }, { status: 401 });
  if (!emailVerified) return json({ error: 'email_not_verified' }, { status: 401 });

  const email = normalizeEmail(emailRaw);
  let user =
    ((await env.DB.prepare('SELECT * FROM users WHERE google_id = ?').bind(sub).first()) as User | null) ??
    ((await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first()) as User | null);

  if (!user) {
    user = { id: crypto.randomUUID(), email, google_id: sub, created_at: new Date().toISOString() };
    await env.DB
      .prepare('INSERT INTO users (id, email, google_id, created_at) VALUES (?, ?, ?, ?)')
      .bind(user.id, user.email, user.google_id, user.created_at)
      .run();
  } else if (user.google_id && user.google_id !== sub) {
    // Prevent silently linking a different Google identity to an existing account.
    return json({ error: 'google_account_already_linked_to_other_identity' }, { status: 409 });
  } else if (!user.google_id) {
    await env.DB.prepare('UPDATE users SET google_id = ? WHERE id = ?').bind(sub, user.id).run();
  }

  const sessionId = await createSession(env.DB, user.id);
  const redirectTo = new URL('/', env.ORIGIN).toString();
  const headers = new Headers({ Location: redirectTo });
  headers.append(
    'Set-Cookie',
    setCookieHeader({
      name: sessionCookieName(),
      value: sessionId,
      httpOnly: true,
      sameSite: 'Lax',
      secure: isSecureRequest(request),
      maxAgeSeconds: 60 * 60 * 24,
    }),
  );
  return new Response(null, { status: 302, headers });
}

export async function handleDPoPRegister(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  const body = await readJson<{
    jwk: JWK;
    member_id?: string;
    enrollment_id: string;
    proof: { signature: string };
  }>(request);
  if (!body.jwk) return json({ error: 'jwk required' }, { status: 400 });
  if (!body.enrollment_id) return json({ error: 'enrollment_id required' }, { status: 400 });
  if (!body.proof?.signature) return json({ error: 'proof.signature required' }, { status: 400 });

  const enrollment = (await env.DB
    .prepare(
      `SELECT * FROM dpop_enrollments
       WHERE id = ? AND user_id = ?
       AND strftime('%s', expires_at) > strftime('%s', 'now')`,
    )
    .bind(body.enrollment_id, user.id)
    .first()) as { id: string; challenge: string; stepup_verified_at?: string | null; completed_at?: string | null } | null;
  if (!enrollment) return json({ error: 'invalid enrollment' }, { status: 400 });
  if (!enrollment.stepup_verified_at) return json({ error: 'stepup_required' }, { status: 403 });
  if (enrollment.completed_at) return json({ error: 'enrollment_already_used' }, { status: 409 });

  // Proof-of-possession: verify signature over enrollment challenge
  const msg = new TextEncoder().encode(`dpop-enroll:${enrollment.id}:${enrollment.challenge}`);
  const sig = base64urlDecodeToUint8Array(body.proof.signature);
  const verifyKey = await crypto.subtle.importKey(
    'jwk',
    body.jwk as JsonWebKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  // Make sure we pass an ArrayBuffer (some type defs widen to ArrayBuffer|SharedArrayBuffer)
  const sigBuf = new Uint8Array(sig).buffer;
  const msgBuf = new Uint8Array(msg).buffer;
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verifyKey, sigBuf, msgBuf);
  if (!ok) return json({ error: 'invalid_proof' }, { status: 401 });

  try {
    const jkt = await registerDPoPKey(user.id, body.jwk, body.member_id, env.DB);
    await env.DB.prepare('UPDATE dpop_enrollments SET completed_at = ? WHERE id = ?').bind(new Date().toISOString(), enrollment.id).run();
    const access_token = await issueIngestAccessToken(env, user.id, jkt);
    return json({ jkt, token_type: 'DPoP', access_token, expires_in: 600 }, { status: 200 });
  } catch (e) {
    return json({ error: (e as Error).message }, { status: 409 });
  }
}

export async function handleDPoPEnrollStart(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  const enrollmentId = crypto.randomUUID();
  const challenge = randomBase64url(32);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

  await env.DB
    .prepare('INSERT INTO dpop_enrollments (id, user_id, challenge, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(enrollmentId, user.id, challenge, createdAt, expiresAt)
    .run();

  return json({ enrollment_id: enrollmentId, challenge, expires_at: expiresAt }, { status: 200 });
}

export async function handleMe(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ logged_in: false }, { status: 200 });
  const row = (await env.DB.prepare('SELECT COUNT(1) AS c FROM webauthn_credentials WHERE user_id = ?').bind(user.id).first()) as
    | { c: number }
    | null;
  const has_passkey = !!row && Number((row as any).c) > 0;
  return json({ logged_in: true, has_passkey, user: { id: user.id, email: user.email } }, { status: 200 });
}

export async function handleLogout(request: Request, env: Env): Promise<Response> {
  const sessionId = getCookie(request, sessionCookieName());
  if (sessionId) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(sessionId).run();
  }
  const response = json({ success: true }, { status: 200 });
  response.headers.set(
    'Set-Cookie',
    setCookieHeader({
      name: sessionCookieName(),
      value: '',
      httpOnly: true,
      sameSite: 'Lax',
      secure: isSecureRequest(request),
      maxAgeSeconds: 0,
    }),
  );
  return response;
}

export async function handleWebAuthnStepUpOptions(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  const body = await readJson<WebAuthnStepUpOptionsReq>(request);
  if (!body.enrollment_id) return json({ error: 'enrollment_id required' }, { status: 400 });

  const enrollment = (await env.DB
    .prepare(
      `SELECT * FROM dpop_enrollments
       WHERE id = ? AND user_id = ?
       AND strftime('%s', expires_at) > strftime('%s', 'now')`,
    )
    .bind(body.enrollment_id, user.id)
    .first()) as { id: string } | null;
  if (!enrollment) return json({ error: 'invalid enrollment' }, { status: 400 });

  const creds = ((await env.DB.prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?').bind(user.id).all()).results ??
    []) as unknown as WebAuthnCredentialRecord[];
  if (creds.length === 0) return json({ error: 'no_passkey_registered' }, { status: 409 });

  const options = await generateAuthenticationOptions({
    rpID: env.RP_ID,
    timeout: 60_000,
    userVerification: 'required',
    allowCredentials: creds.map((c) => ({ id: c.credential_id })),
  });

  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await env.DB
    .prepare('INSERT INTO webauthn_challenges (id, type, challenge, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), `stepup:${enrollment.id}`, options.challenge, user.id, user.email, createdAt, expiresAt)
    .run();

  return json({ options }, { status: 200 });
}

export async function handleWebAuthnStepUpVerify(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  const body = await readJson<WebAuthnStepUpVerifyReq>(request);
  if (!body.enrollment_id || !body.credential) return json({ error: 'invalid request' }, { status: 400 });

  const clientChallenge = extractClientChallenge(body.credential);
  if (!clientChallenge) return json({ error: 'missing client challenge' }, { status: 400 });

  const challengeRow = (await env.DB
    .prepare(
      `SELECT * FROM webauthn_challenges
       WHERE user_id = ? AND type = ? AND challenge = ?
       AND strftime('%s', expires_at) > strftime('%s', 'now')
       ORDER BY created_at DESC LIMIT 1`,
    )
    .bind(user.id, `stepup:${body.enrollment_id}`, clientChallenge)
    .first()) as { id: string; challenge: string } | null;
  if (!challengeRow) return json({ error: 'challenge not found or expired' }, { status: 400 });

  const cred = body.credential as AuthenticationResponseJSON;
  const credRow = (await env.DB
    .prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?')
    .bind(cred.id, user.id)
    .first()) as WebAuthnCredentialRecord | null;
  if (!credRow) return json({ error: 'unknown credential' }, { status: 401 });

  const authenticator = {
    credentialID: credRow.credential_id,
    credentialPublicKey: base64urlDecodeToUint8Array(credRow.public_key),
    counter: credRow.counter,
    transports: (credRow.transports ? (JSON.parse(credRow.transports) as unknown[]) : []) as any,
  };

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: cred,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      authenticator,
      requireUserVerification: true,
    });
  } catch (e) {
    return json({ error: 'webauthn stepup error', detail: String(e) }, { status: 400 });
  }
  if (!verification.verified || !verification.authenticationInfo) return json({ error: 'webauthn stepup failed' }, { status: 401 });

  await env.DB
    .prepare('UPDATE webauthn_credentials SET counter = ? WHERE credential_id = ?')
    .bind(verification.authenticationInfo.newCounter, credRow.credential_id)
    .run();

  await env.DB
    .prepare('UPDATE dpop_enrollments SET stepup_verified_at = ? WHERE id = ? AND user_id = ?')
    .bind(new Date().toISOString(), body.enrollment_id, user.id)
    .run();

  // Best-effort: consume challenge
  await env.DB.prepare('DELETE FROM webauthn_challenges WHERE id = ?').bind(challengeRow.id).run();

  return json({ success: true }, { status: 200 });
}

export async function handleWebAuthnEnrollOptions(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  const creds = ((await env.DB.prepare('SELECT * FROM webauthn_credentials WHERE user_id = ?').bind(user.id).all()).results ??
    []) as unknown as WebAuthnCredentialRecord[];
  // Allow adding additional passkeys for the same user (e.g. new device / phone).
  // We still exclude existing credential IDs to avoid duplicate registrations.

  const options = await generateRegistrationOptions({
    rpName: env.WEBAUTHN_RP_NAME,
    rpID: env.RP_ID,
    userID: new TextEncoder().encode(user.id),
    userName: user.email,
    timeout: 60_000,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    supportedAlgorithmIDs: [...WEBAUTHN_ALGS_ES256],
    excludeCredentials: creds.map((c) => ({ id: c.credential_id })),
  });

  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await env.DB
    .prepare('INSERT INTO webauthn_challenges (id, type, challenge, user_id, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), 'enroll-registration', options.challenge, user.id, user.email, createdAt, expiresAt)
    .run();

  return json({ options }, { status: 200 });
}

export async function handleWebAuthnEnrollVerify(request: Request, env: Env): Promise<Response> {
  const user = await getSessionUser(request, env.DB);
  if (!user) return json({ error: 'unauthorized' }, { status: 401 });

  const body = await readJson<WebAuthnEnrollVerifyReq>(request);
  if (!body.credential) return json({ error: 'invalid request' }, { status: 400 });

  const clientChallenge = extractClientChallenge(body.credential);
  if (!clientChallenge) return json({ error: 'missing client challenge' }, { status: 400 });

  const challengeRow = (await env.DB
    .prepare(
      `SELECT * FROM webauthn_challenges
       WHERE user_id = ? AND type = ? AND challenge = ?
       AND strftime('%s', expires_at) > strftime('%s', 'now')
       ORDER BY created_at DESC LIMIT 1`,
    )
    .bind(user.id, 'enroll-registration', clientChallenge)
    .first()) as { id: string; challenge: string } | null;
  if (!challengeRow) return json({ error: 'challenge not found or expired' }, { status: 400 });

  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: body.credential,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: env.ORIGIN,
      expectedRPID: env.RP_ID,
      supportedAlgorithmIDs: [...WEBAUTHN_ALGS_ES256],
    });
  } catch (e) {
    return json({ error: 'webauthn enroll verify error', detail: String(e) }, { status: 400 });
  }

  if (!verification.verified || !verification.registrationInfo) return json({ error: 'webauthn enroll verify failed' }, { status: 401 });

  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
  try {
    await env.DB
      .prepare('INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .bind(crypto.randomUUID(), user.id, credentialID, base64urlEncode(credentialPublicKey), counter, JSON.stringify(body.credential.response.transports ?? []), new Date().toISOString())
      .run();
  } catch (e) {
    return json({ error: 'failed to store credential', detail: String(e) }, { status: 409 });
  }

  // Best-effort: consume challenge
  await env.DB.prepare('DELETE FROM webauthn_challenges WHERE id = ?').bind(challengeRow.id).run();

  return json({ success: true }, { status: 200 });
}