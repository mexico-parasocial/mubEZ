-- OAuth mobile handoff (Phase C): native apps complete sign-in via a
-- one-time exchange code instead of receiving tokens in the callback JSON.
ALTER TABLE oauth_login_attempts ADD COLUMN return_to TEXT NULL;

CREATE TABLE IF NOT EXISTS oauth_exchange_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  attempt_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_exchange_codes_hash ON oauth_exchange_codes(code_hash);
