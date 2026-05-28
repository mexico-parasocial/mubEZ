CREATE TABLE IF NOT EXISTS karma (
  id TEXT PRIMARY KEY,
  anonymous_profile_id TEXT NOT NULL,
  community_id TEXT,
  action_type TEXT NOT NULL,
  points INTEGER NOT NULL DEFAULT 0,
  detail_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (anonymous_profile_id) REFERENCES anonymous_profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_karma_profile ON karma(anonymous_profile_id);
CREATE INDEX IF NOT EXISTS idx_karma_community ON karma(community_id);
CREATE INDEX IF NOT EXISTS idx_karma_action ON karma(action_type);

CREATE TABLE IF NOT EXISTS karma_revelation (
  anonymous_profile_id TEXT PRIMARY KEY,
  reveal_global INTEGER NOT NULL DEFAULT 0,
  reveal_communities_json TEXT NOT NULL DEFAULT '[]',
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (anonymous_profile_id) REFERENCES anonymous_profiles(id) ON DELETE CASCADE
);
