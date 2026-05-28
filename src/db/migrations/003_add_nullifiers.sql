-- Migration 003: Add nullifiers table for sybil-resistance

CREATE TABLE IF NOT EXISTS nullifiers (
  id TEXT PRIMARY KEY,
  nullifier TEXT NOT NULL,
  community_id TEXT NOT NULL,
  commitment TEXT NOT NULL,
  session_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (nullifier, community_id),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_nullifiers_community ON nullifiers(community_id);
CREATE INDEX IF NOT EXISTS idx_nullifiers_commitment ON nullifiers(commitment);
