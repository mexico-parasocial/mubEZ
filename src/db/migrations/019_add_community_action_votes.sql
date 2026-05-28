-- Migration 019: Add community_action_votes table

CREATE TABLE IF NOT EXISTS community_action_votes (
  action_id TEXT NOT NULL,
  admin_did TEXT NOT NULL,
  vote TEXT NOT NULL,
  vote_signature TEXT NOT NULL,
  voted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (action_id, admin_did),
  FOREIGN KEY (action_id) REFERENCES community_actions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_community_action_votes_action ON community_action_votes(action_id);
