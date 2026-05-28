-- Migration 017: Add community_memberships table

CREATE TABLE IF NOT EXISTS community_memberships (
  community_id TEXT NOT NULL,
  member_did TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  membership_record_uri TEXT,
  group_record_uri TEXT,
  joined_at TEXT,
  left_at TEXT,
  PRIMARY KEY (community_id, member_did),
  FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_community_memberships_community ON community_memberships(community_id);
CREATE INDEX IF NOT EXISTS idx_community_memberships_member ON community_memberships(member_did);
CREATE INDEX IF NOT EXISTS idx_community_memberships_status ON community_memberships(status);
