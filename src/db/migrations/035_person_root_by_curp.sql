-- Migration 035: File person roots under the credential, not the session.
--
-- `person_roots.session_id UNIQUE` meant a second session minted a second
-- person, and the only guard — one registration per ZK commitment — deduplicated
-- on a value the client chooses (the commitment's salt). Re-enrolling with a
-- fresh salt therefore produced a second person who could vote again on the
-- same subject. One person, one vote did not hold.
--
-- The anchor is `person_key`: HMAC(pepper, 'person-root' ‖ curp_hash), derived
-- from the deterministic CURP hash of CD-1 so the same human always resolves to
-- the same root. It is a second derivation rather than the curp_hash itself, so
-- these rows cannot be joined to the credential claims by equality.
--
-- Rows predating this migration keep a NULL key: they were filed under a
-- session and there is no CURP to re-derive from. SQLite allows repeated NULLs
-- under UNIQUE, so they persist untouched and simply stop being resolved to.

PRAGMA foreign_keys = OFF;

CREATE TABLE person_roots_new (
  id TEXT PRIMARY KEY,
  person_key TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO person_roots_new (id, person_key, status, created_at, updated_at)
SELECT id, NULL, status, created_at, updated_at FROM person_roots;

DROP TABLE person_roots;
ALTER TABLE person_roots_new RENAME TO person_roots;

-- Where the vote path reads the anchor from: the session's own INE artifact.
ALTER TABLE proof_artifacts ADD COLUMN person_key TEXT;

CREATE INDEX IF NOT EXISTS idx_proof_artifacts_person_key
ON proof_artifacts(person_key);

PRAGMA foreign_keys = ON;
