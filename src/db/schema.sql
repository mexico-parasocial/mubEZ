-- Muvis Schema v1

CREATE TABLE IF NOT EXISTS migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  handle TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  authorization_server TEXT NOT NULL DEFAULT '',
  authenticated_at TEXT NOT NULL DEFAULT (datetime('now')),
  pds_safety_json TEXT NOT NULL DEFAULT '{}',
  active_persona_id TEXT NOT NULL DEFAULT 'orbit',
  active_surface_id TEXT NOT NULL DEFAULT 'public',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS provider_status (
  session_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  availability TEXT NOT NULL DEFAULT 'offline',
  compatibility TEXT NOT NULL DEFAULT 'needs-review',
  policy_record TEXT NOT NULL DEFAULT '',
  compatibility_record TEXT NOT NULL DEFAULT '',
  last_sync_at TEXT NOT NULL DEFAULT (datetime('now')),
  supported_claims_json TEXT NOT NULL DEFAULT '[]',
  notes TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (session_id, provider_id),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS claim_requests (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  app_name TEXT NOT NULL,
  app_kind TEXT NOT NULL,
  surface TEXT NOT NULL,
  requested_claims_json TEXT NOT NULL,
  proof_mode TEXT NOT NULL DEFAULT 'proof-only',
  status TEXT NOT NULL DEFAULT 'pending',
  reason TEXT NOT NULL DEFAULT '',
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  issued_at TEXT,
  last_used_at TEXT,
  expires_at TEXT,
  grant_id TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  request_id TEXT,
  session_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  app_name TEXT NOT NULL,
  app_kind TEXT NOT NULL,
  surface TEXT NOT NULL,
  requested_claims_json TEXT NOT NULL,
  proof_mode TEXT NOT NULL DEFAULT 'proof-only',
  status TEXT NOT NULL DEFAULT 'pending',
  reason TEXT NOT NULL DEFAULT '',
  requested_at TEXT NOT NULL DEFAULT (datetime('now')),
  issued_at TEXT,
  last_used_at TEXT,
  expires_at TEXT,
  proof_artifact_ids_json TEXT NOT NULL DEFAULT '[]',
  issuer_id TEXT NOT NULL DEFAULT 'm8.broker',
  review_note TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS proof_artifacts (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  request_id TEXT,
  claim_type TEXT NOT NULL,
  requested_value TEXT,
  outcome TEXT NOT NULL,
  statement TEXT NOT NULL DEFAULT '',
  proof_mode TEXT NOT NULL DEFAULT 'proof-only',
  issuer_id TEXT NOT NULL DEFAULT 'm8.broker',
  verifier_id TEXT NOT NULL DEFAULT 'm8.broker',
  audience_app_id TEXT NOT NULL,
  audience_app_name TEXT NOT NULL,
  surface TEXT NOT NULL,
  reference TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at TEXT,
  revoked_at TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
  FOREIGN KEY (grant_id) REFERENCES grants(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS identity_requests (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  audience_app_id TEXT NOT NULL,
  audience_app_name TEXT NOT NULL,
  purpose TEXT NOT NULL,
  merchant_identifier TEXT NOT NULL,
  requested_elements_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  used_at TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_key_backups (
  session_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  encryption_metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

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

CREATE TABLE IF NOT EXISTS did_cache (
  did TEXT PRIMARY KEY,
  doc TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hour'))
);

CREATE TABLE IF NOT EXISTS person_roots (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS person_aliases (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  did TEXT NOT NULL,
  handle TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  UNIQUE (person_id, did),
  FOREIGN KEY (person_id) REFERENCES person_roots(id) ON DELETE CASCADE,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS civic_vote_nullifiers (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  alias_did TEXT NOT NULL,
  subject_uri TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  vote_nullifier TEXT NOT NULL,
  proof_ref TEXT NOT NULL,
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (person_id, subject_type, subject_uri),
  UNIQUE (subject_type, subject_uri, vote_nullifier),
  FOREIGN KEY (person_id) REFERENCES person_roots(id) ON DELETE CASCADE,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_claim_requests_session ON claim_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_claim_requests_status ON claim_requests(status);
CREATE INDEX IF NOT EXISTS idx_grants_session ON grants(session_id);
CREATE INDEX IF NOT EXISTS idx_grants_status ON grants(status);
CREATE INDEX IF NOT EXISTS idx_grants_app_id ON grants(app_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_session ON proof_artifacts(session_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_grant ON proof_artifacts(grant_id);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_status ON proof_artifacts(status);
CREATE INDEX IF NOT EXISTS idx_ledger_session ON ledger(session_id);
CREATE INDEX IF NOT EXISTS idx_identity_requests_session ON identity_requests(session_id);
CREATE INDEX IF NOT EXISTS idx_identity_requests_status ON identity_requests(status);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_identities_session ON anonymous_identities(session_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_identity_posts_identity ON anonymous_identity_posts(identity_id);
CREATE INDEX IF NOT EXISTS idx_anonymous_identity_posts_uri ON anonymous_identity_posts(post_uri);
CREATE INDEX IF NOT EXISTS idx_anonymous_dm_connections_identity ON anonymous_dm_connections(identity_id);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_session ON trusted_devices(session_id);
CREATE INDEX IF NOT EXISTS idx_device_trust_events_session ON device_trust_events(session_id);
CREATE INDEX IF NOT EXISTS idx_did_cache_expires ON did_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_person_aliases_did ON person_aliases(did);
CREATE INDEX IF NOT EXISTS idx_person_aliases_session ON person_aliases(session_id);
CREATE INDEX IF NOT EXISTS idx_civic_vote_nullifiers_subject ON civic_vote_nullifiers(subject_type, subject_uri);
CREATE INDEX IF NOT EXISTS idx_civic_vote_nullifiers_person ON civic_vote_nullifiers(person_id);

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

CREATE TABLE IF NOT EXISTS community_admins (
  community_id TEXT NOT NULL,
  admin_did TEXT NOT NULL,
  added_by_did TEXT,
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  status TEXT NOT NULL DEFAULT 'active',
  PRIMARY KEY (community_id, admin_did),
  FOREIGN KEY (community_id) REFERENCES communities(id) ON DELETE CASCADE
);

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

CREATE TABLE IF NOT EXISTS community_action_votes (
  action_id TEXT NOT NULL,
  admin_did TEXT NOT NULL,
  vote TEXT NOT NULL,
  vote_signature TEXT NOT NULL,
  voted_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (action_id, admin_did),
  FOREIGN KEY (action_id) REFERENCES community_actions(id) ON DELETE CASCADE
);

-- Community indexes
CREATE INDEX IF NOT EXISTS idx_communities_did ON communities(did);
CREATE INDEX IF NOT EXISTS idx_communities_status ON communities(status);
CREATE INDEX IF NOT EXISTS idx_communities_created_by ON communities(created_by_did);
CREATE INDEX IF NOT EXISTS idx_community_admins_community ON community_admins(community_id);
CREATE INDEX IF NOT EXISTS idx_community_admins_did ON community_admins(admin_did);
CREATE INDEX IF NOT EXISTS idx_community_memberships_community ON community_memberships(community_id);
CREATE INDEX IF NOT EXISTS idx_community_memberships_member ON community_memberships(member_did);
CREATE INDEX IF NOT EXISTS idx_community_memberships_status ON community_memberships(status);
CREATE INDEX IF NOT EXISTS idx_community_actions_community ON community_actions(community_id);
CREATE INDEX IF NOT EXISTS idx_community_actions_status ON community_actions(status);
CREATE INDEX IF NOT EXISTS idx_community_actions_pending ON community_actions(status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_community_action_votes_action ON community_action_votes(action_id);
