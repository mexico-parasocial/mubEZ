-- Follower graph for anonymous identities, tier-enforced: follows may only
-- target the default anonymous profile ("main voice"). Isolated burner
-- identities (anonymous_identities) are structurally not followable — a
-- follower graph would break their unlinkability.
CREATE TABLE IF NOT EXISTS anonymous_follows (
  id TEXT PRIMARY KEY,
  follower_session_id TEXT NOT NULL,
  followed_profile_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (follower_session_id, followed_profile_id),
  FOREIGN KEY (follower_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
  FOREIGN KEY (followed_profile_id) REFERENCES anonymous_profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_anonymous_follows_profile ON anonymous_follows(followed_profile_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_follows_follower ON anonymous_follows(follower_session_id);
