-- Migration 012: Add private person aliases and civic vote nullifiers

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

CREATE INDEX IF NOT EXISTS idx_person_aliases_did ON person_aliases(did);
CREATE INDEX IF NOT EXISTS idx_person_aliases_session ON person_aliases(session_id);
CREATE INDEX IF NOT EXISTS idx_civic_vote_nullifiers_subject ON civic_vote_nullifiers(subject_type, subject_uri);
CREATE INDEX IF NOT EXISTS idx_civic_vote_nullifiers_person ON civic_vote_nullifiers(person_id);
