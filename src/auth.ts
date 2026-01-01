import { User } from './types';
import { registerDPoPKey } from './dpop';

export async function handleWebAuthnOptions(request: Request, db: D1Database): Promise<Response> {
  // Placeholder for WebAuthn options
  const options = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: 'DPoP Login', id: 'login.access.example.com' },
    user: { id: crypto.getRandomValues(new Uint8Array(32)), name: 'user@example.com', displayName: 'User' },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
    timeout: 60000,
    attestation: 'direct'
  };
  return new Response(JSON.stringify(options), { headers: { 'Content-Type': 'application/json' } });
}

export async function handleWebAuthnVerify(request: Request, db: D1Database): Promise<Response> {
  // Placeholder for WebAuthn verify
  const body = await request.json();
  // Verify credential
  // For simplicity, assume success and create user
  const userId = crypto.randomUUID();
  await db.prepare('INSERT INTO users (id, email, webauthn_credential_id, webauthn_public_key, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(userId, 'user@example.com', body.id, JSON.stringify(body), new Date().toISOString()).run();
  // Set session cookie
  const response = new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
  response.headers.set('Set-Cookie', `session=${userId}; HttpOnly; Secure; SameSite=Strict`);
  return response;
}

export async function handleGoogleStart(request: Request): Promise<Response> {
  const state = crypto.randomUUID();
  const codeVerifier = crypto.getRandomValues(new Uint8Array(32));
  const codeChallenge = await crypto.subtle.digest('SHA-256', codeVerifier).then(b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''));
  // Redirect to Google
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent('https://login.access.example.com/v1/auth/google/callback')}&response_type=code&scope=openid email&state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  return Response.redirect(url);
}

export async function handleGoogleCallback(request: Request, db: D1Database): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  // Exchange code for token
  // Placeholder
  const userInfo = { email: 'user@gmail.com', sub: 'google-id' };
  let user = await db.prepare('SELECT * FROM users WHERE google_id = ?').bind(userInfo.sub).first() as User | null;
  if (!user) {
    user = { id: crypto.randomUUID(), email: userInfo.email, google_id: userInfo.sub, created_at: new Date().toISOString() };
    await db.prepare('INSERT INTO users (id, email, google_id, created_at) VALUES (?, ?, ?, ?)').bind(user.id, user.email, user.google_id, user.created_at).run();
  }
  const response = new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
  response.headers.set('Set-Cookie', `session=${user.id}; HttpOnly; Secure; SameSite=Strict`);
  return response;
}

export async function handleDPoPRegister(request: Request, db: D1Database): Promise<Response> {
  const session = request.headers.get('Cookie')?.match(/session=([^;]+)/)?.[1];
  if (!session) return new Response('Unauthorized', { status: 401 });
  const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(session).first() as User | null;
  if (!user) return new Response('Unauthorized', { status: 401 });
  const body = await request.json();
  const jkt = await registerDPoPKey(user.id, body.jwk, body.member_id, db);
  return new Response(JSON.stringify({ jkt }), { headers: { 'Content-Type': 'application/json' } });
}