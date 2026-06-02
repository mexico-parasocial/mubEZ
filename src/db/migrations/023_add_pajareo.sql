CREATE TABLE IF NOT EXISTS pajareo_entries (
  id TEXT PRIMARY KEY,
  representative_id TEXT NOT NULL,
  anonymous_identity_id TEXT NOT NULL,
  entry_type TEXT NOT NULL,
  body TEXT NOT NULL,
  anonymous_display_area TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'visible',
  support_count INTEGER NOT NULL DEFAULT 0,
  report_count INTEGER NOT NULL DEFAULT 0,
  response_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (anonymous_identity_id) REFERENCES anonymous_identities(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pajareo_responses (
  id TEXT PRIMARY KEY,
  entry_id TEXT NOT NULL,
  responder_session_id TEXT NOT NULL,
  responder_did TEXT NOT NULL,
  responder_display_name TEXT,
  response_kind TEXT NOT NULL DEFAULT 'public',
  official_entity_id TEXT,
  official_entity_name TEXT,
  official_controller_hash TEXT,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (entry_id) REFERENCES pajareo_entries(id) ON DELETE CASCADE,
  FOREIGN KEY (responder_session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pajareo_entry_supports (
  entry_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (entry_id, session_id),
  FOREIGN KEY (entry_id) REFERENCES pajareo_entries(id) ON DELETE CASCADE,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pajareo_entry_reports (
  entry_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (entry_id, session_id),
  FOREIGN KEY (entry_id) REFERENCES pajareo_entries(id) ON DELETE CASCADE,
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pajareo_entries_representative ON pajareo_entries(representative_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_pajareo_entries_identity ON pajareo_entries(anonymous_identity_id);
CREATE INDEX IF NOT EXISTS idx_pajareo_responses_entry ON pajareo_responses(entry_id, created_at);
