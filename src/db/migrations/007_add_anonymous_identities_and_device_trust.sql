CREATE TABLE IF NOT EXISTS anonymous_identities (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  avatar_seed TEXT NOT NULL,
  nullifier_secret_hash TEXT NOT NULL,
  surface TEXT NOT NULL DEFAULT 'civic',
  community_uri TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  device_trust_state TEXT NOT NULL DEFAULT 'unknown',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  archived_at TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS anonymous_identity_posts (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  post_uri TEXT NOT NULL UNIQUE,
  community_uri TEXT,
  post_type TEXT NOT NULL DEFAULT 'post',
  proof_artifact_ids_json TEXT NOT NULL DEFAULT '[]',
  dm_policy TEXT NOT NULL DEFAULT 'off',
  reply_count INTEGER NOT NULL DEFAULT 0,
  repost_count INTEGER NOT NULL DEFAULT 0,
  like_count INTEGER NOT NULL DEFAULT 0,
  quote_count INTEGER NOT NULL DEFAULT 0,
  thread_count INTEGER NOT NULL DEFAULT 0,
  stats_synced_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (identity_id) REFERENCES anonymous_identities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS anonymous_dm_connections (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL,
  provider TEXT NOT NULL DEFAULT 'germ',
  provider_ref TEXT NOT NULL DEFAULT '',
  contact_url TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'germ-card-link',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  FOREIGN KEY (identity_id) REFERENCES anonymous_identities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trusted_devices (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  platform TEXT NOT NULL,
  device_key_id TEXT NOT NULL,
  public_key TEXT NOT NULL DEFAULT '',
  attestation_status TEXT NOT NULL DEFAULT 'unverified',
  risk_tier TEXT NOT NULL DEFAULT 'low',
  last_verified_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(session_id, device_key_id),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS device_trust_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  device_id TEXT,
  action TEXT NOT NULL,
  result TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_anonymous_identities_session ON anonymous_identities(session_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_identity_posts_identity ON anonymous_identity_posts(identity_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_identity_posts_uri ON anonymous_identity_posts(post_uri);
CREATE INDEX IF NOT EXISTS idx_anonymous_dm_connections_identity ON anonymous_dm_connections(identity_id);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_session ON trusted_devices(session_id);
CREATE INDEX IF NOT EXISTS idx_device_trust_events_session ON device_trust_events(session_id);
