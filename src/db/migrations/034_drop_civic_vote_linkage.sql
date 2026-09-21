-- Migration 034: Remove the account-to-vote linkage from the civic vote path.
--
-- CD-12. `civic_vote_nullifiers` kept `session_id` and `alias_did`, and
-- `person_aliases` kept `session_id`, so a person root could be joined to the
-- user's account DID and from there to their public profile. One person, one
-- vote needs `person_id` and the uniqueness constraint below and nothing else:
-- authorisation runs on `person.id` and `identity_pub_civic` is never
-- presented (OD-7 §5a), so those columns were observational.

PRAGMA foreign_keys = OFF;

CREATE TABLE civic_vote_nullifiers_new (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL,
  subject_uri TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  vote_nullifier TEXT NOT NULL,
  proof_ref TEXT NOT NULL,
  issued_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (person_id, subject_type, subject_uri),
  UNIQUE (subject_type, subject_uri, vote_nullifier),
  FOREIGN KEY (person_id) REFERENCES person_roots(id) ON DELETE CASCADE
);

INSERT INTO civic_vote_nullifiers_new
  (id, person_id, subject_uri, subject_type, vote_nullifier, proof_ref, issued_at, last_used_at)
SELECT id, person_id, subject_uri, subject_type, vote_nullifier, proof_ref, issued_at, last_used_at
FROM civic_vote_nullifiers;

DROP TABLE civic_vote_nullifiers;
ALTER TABLE civic_vote_nullifiers_new RENAME TO civic_vote_nullifiers;

CREATE TABLE person_aliases_new (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL,
  did TEXT NOT NULL,
  handle TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT,
  UNIQUE (person_id, did),
  FOREIGN KEY (person_id) REFERENCES person_roots(id) ON DELETE CASCADE
);

INSERT INTO person_aliases_new
  (id, person_id, did, handle, status, created_at, updated_at, revoked_at)
SELECT id, person_id, did, handle, status, created_at, updated_at, revoked_at
FROM person_aliases;

DROP TABLE person_aliases;
ALTER TABLE person_aliases_new RENAME TO person_aliases;

PRAGMA foreign_keys = ON;
