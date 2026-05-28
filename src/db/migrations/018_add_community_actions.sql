-- Migration 018: Add community_actions table

CREATE TABLE IF NOT EXISTS community_actions (
  id TEXT PRIMARY KEY,
  community_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  impact_level TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  proposed_by_did TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  required_approvals INTEGER NOT NULL,
  current_approvals INTEGER NOT NULL DEFAULT 0,
  repo_commit_cid TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  executed_at TEXT,
  failed_reason TEXT,
  FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_community_actions_community ON community_actions(community_id);
CREATE INDEX IF NOT EXISTS idx_community_actions_status ON community_actions(status);
CREATE INDEX IF NOT EXISTS idx_community_actions_pending ON community_actions(status) WHERE status = 'pending';
