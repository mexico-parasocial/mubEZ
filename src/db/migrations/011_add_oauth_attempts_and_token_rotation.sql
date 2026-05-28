-- Migration 011: OAuth login attempts, session state, and refresh-token rotation

CREATE TABLE IF NOT EXISTS oauth_login_attempts (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL UNIQUE,
  identifier TEXT NOT NULL,
  oauth_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  completed_at TEXT,
  failed_at TEXT,
  resolved_did TEXT,
  session_id TEXT,
  error_code TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_login_attempts_state ON oauth_login_attempts(state);
CREATE INDEX IF NOT EXISTS idx_oauth_login_attempts_status ON oauth_login_attempts(status);
CREATE INDEX IF NOT EXISTS idx_oauth_login_attempts_expires ON oauth_login_attempts(expires_at);

ALTER TABLE sessions ADD COLUMN status TEXT NOT NULL DEFAULT 'active';

ALTER TABLE refresh_tokens ADD COLUMN rotated_at TEXT;
ALTER TABLE refresh_tokens ADD COLUMN replaced_by_token_hash TEXT;
