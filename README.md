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
3. Initialize D1: `wrangler d1 execute dpop_db --file=./schemas/init.sql`
4. Run locally: `npm run dev`
5. Deploy: `npm run deploy`

## API Endpoints

- `POST /v1/auth/webauthn/options`: Get WebAuthn options
- `POST /v1/auth/webauthn/verify`: Verify WebAuthn credential
- `GET /v1/auth/google/start`: Start Google OAuth
- `GET /v1/auth/google/callback`: Handle Google OAuth callback
- `POST /v1/dpop/register`: Register DPoP key (requires session)
- `POST /v1/ingest/event`: Ingest event (requires DPoP header)
- `GET /v1/export/canonical`: Export canonical events

## Testing

Run tests: `npm test`

## Schemas

See `schemas/init.sql` for D1 table definitions.