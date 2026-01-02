-- Users table
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  google_id TEXT,
  webauthn_credential_id TEXT,
  webauthn_public_key TEXT,
  created_at TEXT NOT NULL
);

-- Sessions (cookie-backed)
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- OAuth PKCE state storage (short-lived)
CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  code_verifier TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- DPoP keys table
CREATE TABLE IF NOT EXISTS dpop_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  jkt TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  member_id TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- DPoP replay protection (TTL enforced in application code)
CREATE TABLE IF NOT EXISTS dpop_replays (
  jti TEXT PRIMARY KEY,
  iat INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

-- DPoP key enrollment sessions (step-up gated)
CREATE TABLE IF NOT EXISTS dpop_enrollments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  challenge TEXT NOT NULL,
  stepup_verified_at TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- WebAuthn challenges (short-lived)
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL, -- 'registration' | 'authentication'
  challenge TEXT NOT NULL,
  user_id TEXT,
  email TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- WebAuthn credentials (passkeys)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  credential_id TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL,
  transports TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Events table
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  jkt TEXT NOT NULL,
  htm TEXT NOT NULL,
  htu TEXT NOT NULL,
  iat INTEGER NOT NULL,
  jti TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Canonicalized output from FDS
CREATE TABLE IF NOT EXISTS canonical_events (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  member_id_canonical TEXT NOT NULL,
  member_id_confidence REAL NOT NULL,
  trust_level TEXT NOT NULL,
  risk_score REAL NOT NULL,
  action TEXT NOT NULL,
  reason_codes TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_dpop_keys_jkt ON dpop_keys(jkt);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
CREATE INDEX IF NOT EXISTS idx_events_jkt ON events(jkt);
CREATE INDEX IF NOT EXISTS idx_events_jti ON events(jti);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_dpop_replays_iat ON dpop_replays(iat);
CREATE INDEX IF NOT EXISTS idx_dpop_enrollments_user_id ON dpop_enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_dpop_enrollments_expires_at ON dpop_enrollments(expires_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_canonical_events_event_id ON canonical_events(event_id);