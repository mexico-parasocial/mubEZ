-- Migration 004: Add anonymous profiles for Anonymous Mode

CREATE TABLE IF NOT EXISTS anonymous_profiles (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  avatar_seed TEXT NOT NULL,
  nullifier_secret TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_anonymous_profiles_session ON anonymous_profiles(session_id);
