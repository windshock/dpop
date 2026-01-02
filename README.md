# DPoP-based Login Site + Event Ingest + FDS Engine

This project implements a DPoP-based authentication system with event ingestion and a Fraud Detection System (FDS) engine using Cloudflare Workers and D1.

## Features

- **Login Site**: Web-based login at `https://login.access.example.com` supporting Passkey (WebAuthn) and Google OIDC.
- **DPoP Registration**: After login, register a DPoP public key bound to the user.
- **Event Ingestion**: Ingest events with DPoP proof verification.
- **FDS Engine**: Analyze events for fraud using various rules.

## Setup

1. Install dependencies: `npm install`
2. Configure `wrangler.toml` with your D1 database ID and Google OAuth credentials.
3. Initialize D1 schema:
   - Remote: `wrangler d1 execute dpop_db --file=./schemas/init.sql`
   - Local: `wrangler d1 execute dpop_db --local --file=./schemas/init.sql`
4. Run locally: `npm run dev -- --local`
5. Deploy: `npm run deploy`

### Local WebAuthn note

WebAuthn requires a secure context. `localhost` is treated as secure, so for local dev set:

- `RP_ID = "localhost"`
- `ORIGIN = "http://localhost:8787"`

in `wrangler.toml` (or your dev-only overrides).

### Google OAuth secrets

Do not commit `GOOGLE_CLIENT_SECRET` to `wrangler.toml`. Use either:

- Wrangler secret: `npx wrangler secret put GOOGLE_CLIENT_SECRET`
- Local dev vars file: create `.dev.vars` (see `.dev.vars.example`)

### Access token signing secret (B plan)

This project issues short-lived access tokens for ingestion, and requires **both**:

- `Authorization: DPoP <access_token>`
- `DPoP: <proof>`

Set `ACCESS_TOKEN_SECRET` (dev-only) in `.dev.vars`, and store it as a Worker secret in production.

## API Endpoints

- `POST /v1/auth/webauthn/options`: Get WebAuthn options
- `POST /v1/auth/webauthn/verify`: Verify WebAuthn credential
- `GET /v1/auth/google/start`: Start Google OAuth
- `GET /v1/auth/google/callback`: Handle Google OAuth callback
- `POST /v1/dpop/register`: Register DPoP key (requires session)
- `POST /v1/dpop/enroll/start`: Start DPoP enrollment (requires session)
- `POST /v1/auth/webauthn/stepup/options`: Get step-up assertion options (requires session + existing passkey)
- `POST /v1/auth/webauthn/stepup/verify`: Verify step-up assertion (requires session)
- `POST /v1/ingest/event`: Ingest event (requires `Authorization: DPoP <token>` and `DPoP` proof)
- `GET /v1/export/canonical`: Export canonical events

## DPoP Verification (what is checked)

The `DPoP` header is expected to be a compact JWT with `typ=dpop+jwt`.

Verification checks:

- `htm` matches the HTTP method
- `htu` matches the request URL (**canonicalized**; see below)
- `iat` is within a time window
- `jti` uniqueness with TTL 120s (replay protection)
- JWT signature validity
- key must already be registered (JWK thumbprint = `jkt` exists in `dpop_keys`)

### DPoP htu canonicalization (important)

To avoid common real-world mismatches, the server compares `htu` using a canonical form:

- **Compare**: `origin + pathname` only (query/fragment ignored)
- **Normalize**: lowercase host, ignore default port (`:80` for http, `:443` for https)
- **Normalize**: trim trailing slash (except `/`)

Recommendation: clients should build `htu` as `window.location.origin + pathname` (no query).

### DPoP header size (jwk vs kid)

This Worker supports both:

- **Simple mode (demo)**: DPoP JWT header includes `jwk` each request (bigger header)
- **Production-friendly mode**: DPoP JWT header includes `kid` (treated as `jkt`) and the server loads the registered public JWK from `dpop_keys`

## Flows (Mermaid)

### Google login (OIDC code flow + PKCE)

```mermaid
sequenceDiagram
  participant U as User/Browser
  participant W as Worker
  participant G as Google

  U->>W: GET /v1/auth/google/start
  W->>W: create oauth_states(state(with nonce), code_verifier, TTL)
  W-->>U: 302 Location: Google auth URL (state+PKCE+nonce)
  U->>G: OAuth authorize
  G-->>U: Redirect to /v1/auth/google/callback?code&state
  U->>W: GET /v1/auth/google/callback?code&state
  W->>W: validate state(one-time, TTL) + exchange code for token
  W->>W: verify id_token (iss/aud/exp/iat/nonce) and extract sub/email
  W->>W: upsert users + create sessions row
  W-->>U: 302 Location: / + Set-Cookie: session=...
```

### Google OIDC verification checklist (implemented)

- **id_token verification**: `iss` / `aud` / `exp` (and `iat` sanity window) + `nonce`
- **state**: one-time (deleted on first use) + TTL enforced
- **redirect_uri**: fixed to `ORIGIN + /v1/auth/google/callback` (not derived from request URL)
- **email usage**: if we use email for account linking, we require `email_verified === true`
- **final identity**: account identity is determined by **`id_token.sub`** (userinfo is not used as the source of truth)

### Passkey login/registration (WebAuthn)

```mermaid
sequenceDiagram
  participant U as User/Browser
  participant W as Worker
  participant A as Authenticator (Passkey)

  U->>W: POST /v1/auth/webauthn/options {email}
  W->>W: create/find user + store webauthn_challenges
  W-->>U: {mode, options}

  alt mode=registration
    U->>A: navigator.credentials.create(options)
    A-->>U: attestation
    U->>W: POST /v1/auth/webauthn/verify {email, mode, credential}
    W->>W: verifyRegistrationResponse + store webauthn_credentials + create session
    W-->>U: 200 + Set-Cookie: session=...
  else mode=authentication
    U->>A: navigator.credentials.get(options)
    A-->>U: assertion
    U->>W: POST /v1/auth/webauthn/verify {email, mode, credential}
    W->>W: verifyAuthenticationResponse + update counter + create session
    W-->>U: 200 + Set-Cookie: session=...
  end
```

### DPoP key enrollment (step-up gated)

```mermaid
sequenceDiagram
  participant U as User/Browser
  participant W as Worker
  participant A as Authenticator (Passkey)

  U->>W: POST /v1/dpop/enroll/start (Cookie: session=...)
  W->>W: create dpop_enrollments(enrollment_id, challenge, TTL)
  W-->>U: {enrollment_id, challenge}

  U->>W: POST /v1/auth/webauthn/stepup/options {enrollment_id} (Cookie: session=...)
  W->>W: create webauthn_challenges(type=stepup:enrollment_id)
  W-->>U: {options}

  U->>A: navigator.credentials.get(options) (userVerification=required)
  A-->>U: assertion

  U->>W: POST /v1/auth/webauthn/stepup/verify {enrollment_id, credential}
  W->>W: verifyAuthenticationResponse + mark enrollment.stepup_verified_at
  W-->>U: {success:true}

  U->>U: generate DPoP keypair (client)
  U->>U: sign "dpop-enroll:enrollment_id:challenge" with DPoP private key

  U->>W: POST /v1/dpop/register {jwk, member_id?, enrollment_id, proof.signature} (Cookie: session=...)
  W->>W: verify stepup + verify signature over challenge + store dpop_keys + mark enrollment completed
  W-->>U: {jkt}
```

### Event ingest (DPoP proof required)

```mermaid
sequenceDiagram
  participant C as Client
  participant W as Worker
  participant DB as D1

  C->>W: POST /v1/ingest/event (DPoP: <jwt>) {member_id,payload}
  W->>DB: replay TTL check (dpop_replays) + key lookup (dpop_keys by jkt)
  W->>W: verify JWT signature + htm/htu/iat/jti
  W->>DB: INSERT events + INSERT canonical_events
  W-->>C: 200 {proof_verified,risk_score,action,trust_level,reason_codes}
```

## Testing

Run tests: `npm test`

## Local ingest demo (DPoP proof)

1. Open `http://localhost:8787/`, login, then click **Generate & Register DPoP Key**
2. The `/v1/dpop/register` response includes a short-lived `access_token` (token_type `DPoP`). For convenience, the demo page also stores it in:

```js
localStorage.getItem('access_token')
```

3. Run the demo sender (set both ACCESS_TOKEN and DPOP_PRIVATE_JWK):

```bash
ACCESS_TOKEN='eyJ...' DPOP_PRIVATE_JWK='{"kty":"EC",...}' node scripts/ingest-demo.mjs http://localhost:8787 1234567
```

Alternatively, you can add the key to `.dev.vars`:

```text
DPOP_PRIVATE_JWK={"kty":"EC",...}
```

And you may also temporarily add the access token to `.dev.vars` for the node script:

```text
ACCESS_TOKEN=eyJ...
```

## Attack demos (showing failures) — 3 scenarios

The ingestion endpoint enforces **B plan**:

- client must send both `Authorization: DPoP <access_token>` and `DPoP: <proof>`
- the server enforces **token↔proof binding**: `token.cnf.jkt === proof.jkt`
- the proof key must be **registered** in `dpop_keys`

### Scenario 1 (A): Stolen access_token alone is useless

**Attacker capability**: steals `access_token` only (no private key).  
**What they try**: call ingest with `Authorization: DPoP <token>` but without `DPoP` header.  
**Expected**: server returns `reason_codes` containing **`PROOF_MISSING`**.

How to reproduce quickly:

- in the demo UI, load a token in the attacker panel and click **Attack A: token only (no DPoP)**.

### Scenario 2 (B): Stolen token + attacker key proof fails (unregistered key)

**Attacker capability**: steals `access_token` (bound to a registered key), but does not have the matching registered private key.  
**What they try**: generate their own (unregistered) key and send a valid DPoP proof for it with the stolen token.  
**Expected**: server rejects with `reason_codes` containing **`UNREGISTERED_KEY`** (and `PROOF_INVALID` wrapper).

How to reproduce in the demo UI:

1. In the attacker panel click **Load current token**
2. Click **Generate unregistered attacker key**
3. Click **Send token + proof**

### Scenario 3 (C): Attacker has server token signing secret but no registered key

**Attacker capability**: has `ACCESS_TOKEN_SECRET` so they can forge access tokens.  
**What they try**: forge a token bound to an attacker key (their own), then send a valid proof for that key.  
**Expected**: server still rejects because the key isn’t registered: `reason_codes` contains **`UNREGISTERED_KEY`**.

This is implemented in the demo UI (test only), and also as a node script:

- Demo UI: use the attacker panel section "Scenario C (test only)" and click the button.

```bash
node scripts/attack-forged-token-unregistered-key.mjs http://localhost:8787 1234567
```

## Schemas

See `schemas/init.sql` for D1 table definitions.