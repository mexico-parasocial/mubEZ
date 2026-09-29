-- Migration 039: nullifier proofs stop publishing the enrollment commitment (CD-16)
--
-- v1 nullifier proofs output `commitment`, the same value for every
-- community an enrollment joined, and `nullifiers` stored it next to the
-- session. Any two communities, or anyone with this table, could link one
-- person's memberships, and the commitment led back to the INE artifact.
--
-- v2 proves membership in the issuer's enrollment tree instead and publishes
-- only its root, which every enrolled person shares.
--   enrollment_leaves: one leaf per enrollment commitment, in issuance order.
--     A leaf counts only while an active INE artifact carries its commitment;
--     otherwise the tree holds zero there.
--   enrollment_roots:  roots the issuer has published, and when each stopped
--     being current, for the acceptance window.
-- Existing nullifiers keep their value (v1 and v2 both compute
-- Poseidon(salt, communityId)), so nobody can join a community twice across
-- the upgrade; their commitment and session_id are dropped.

PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS enrollment_leaves (
  leaf_index INTEGER PRIMARY KEY,
  commitment TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO enrollment_leaves (commitment, created_at)
SELECT commitment, issued_at FROM proof_artifacts
WHERE commitment IS NOT NULL AND request_id = 'ine-verification'
ORDER BY issued_at, id;

CREATE TABLE IF NOT EXISTS enrollment_roots (
  root TEXT PRIMARY KEY,
  first_seen_at TEXT NOT NULL,
  superseded_at TEXT
);

CREATE TABLE nullifiers_new (
  id TEXT PRIMARY KEY,
  nullifier TEXT NOT NULL,
  community_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (nullifier, community_id)
);

INSERT INTO nullifiers_new (id, nullifier, community_id, created_at)
SELECT id, nullifier, community_id, created_at FROM nullifiers;

DROP TABLE nullifiers;
ALTER TABLE nullifiers_new RENAME TO nullifiers;

CREATE INDEX IF NOT EXISTS idx_nullifiers_community ON nullifiers(community_id);

PRAGMA foreign_keys = ON;
