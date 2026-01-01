-- Users table
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  google_id TEXT,
  webauthn_credential_id TEXT,
  webauthn_public_key TEXT,
  created_at TEXT NOT NULL
);

-- DPoP keys table
CREATE TABLE dpop_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  jkt TEXT UNIQUE NOT NULL,
  public_key TEXT NOT NULL,
  member_id TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Events table
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  jkt TEXT NOT NULL,
  htm TEXT NOT NULL,
  htu TEXT NOT NULL,
  iat INTEGER NOT NULL,
  jti TEXT UNIQUE NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Indexes
CREATE INDEX idx_dpop_keys_jkt ON dpop_keys(jkt);
CREATE INDEX idx_events_jkt ON events(jkt);
CREATE INDEX idx_events_jti ON events(jti);
CREATE INDEX idx_events_created_at ON events(created_at);