-- Migration 015: Add communities table

CREATE TABLE IF NOT EXISTS communities (
  id TEXT PRIMARY KEY,
  did TEXT UNIQUE NOT NULL,
  handle TEXT UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  manifesto_cid TEXT,
  political_compass_x REAL,
  political_compass_y REAL,
  ruleset_cid TEXT,
  pds_host TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending_admins',
  created_by_did TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_communities_did ON communities(did);
CREATE INDEX IF NOT EXISTS idx_communities_status ON communities(status);
CREATE INDEX IF NOT EXISTS idx_communities_created_by ON communities(created_by_did);
