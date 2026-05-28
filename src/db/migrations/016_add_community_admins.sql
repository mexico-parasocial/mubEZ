-- Migration 016: Add community_admins table

CREATE TABLE IF NOT EXISTS community_admins (
  community_id TEXT NOT NULL,
  admin_did TEXT NOT NULL,
  added_by_did TEXT,
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'active',
  PRIMARY KEY (community_id, admin_did),
  FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_community_admins_community ON community_admins(community_id);
CREATE INDEX IF NOT EXISTS idx_community_admins_did ON community_admins(admin_did);
