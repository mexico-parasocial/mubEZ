-- Migration 039: issuer age tree for v3 unlinkable age proofs (CD-16)
--
-- The issuer side of docs/V3_UNLINKABLE_AGE_PROOFS.md: a Poseidon Merkle tree
-- (depth 20) whose leaves are Poseidon(H, birthDay, expiryDay), where H is a
-- hiding commitment the wallet made to its device-held secret and birthDay is
-- taken from the INE record, never from the client.
--
-- age_tree_leaves is the private source of truth: which enrollment each leaf
-- belongs to, so revoking the enrollment takes the leaf out of the tree. It is
-- never published. The leaf value is kept after its slot is zeroed, so a
-- holder can later prove knowledge of the preimage to refresh it.
--
-- age_tree_nodes is the public tree, derived from the leaves: (level, index)
-- -> hash, level 0 being the leaves. Missing nodes are the zero subtree.
--
-- age_tree_roots: one row per tree version, signed by the issuer key once
-- published. Unsigned rows are never served.

CREATE TABLE IF NOT EXISTS age_tree_leaves (
  leaf_index INTEGER PRIMARY KEY,
  leaf TEXT NOT NULL,
  -- Deliberately not a foreign key: a cascade would delete the row while its
  -- node is still in the tree. A missing enrollment zeroes the leaf instead.
  proof_artifact_id TEXT NOT NULL,
  expiry_day INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'replaced')),
  in_tree INTEGER NOT NULL DEFAULT 0 CHECK (in_tree IN (0, 1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_age_tree_leaves_artifact ON age_tree_leaves(proof_artifact_id);
CREATE INDEX IF NOT EXISTS idx_age_tree_leaves_in_tree ON age_tree_leaves(in_tree, expiry_day);
-- One live leaf per enrollment: a refresh replaces, it does not add.
CREATE UNIQUE INDEX IF NOT EXISTS idx_age_tree_leaves_one_active
  ON age_tree_leaves(proof_artifact_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS age_tree_nodes (
  level INTEGER NOT NULL,
  node_index INTEGER NOT NULL,
  hash TEXT NOT NULL,
  PRIMARY KEY (level, node_index)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS age_tree_roots (
  version INTEGER PRIMARY KEY,
  root TEXT NOT NULL,
  size INTEGER NOT NULL,
  issued_at TEXT NOT NULL,
  issuer_did TEXT,
  key_id TEXT,
  signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_age_tree_roots_root ON age_tree_roots(root);

-- The iM8 wallet hands H over with its holder binding (CD-14 relay), so the
-- secret behind it never passes through PARA.
ALTER TABLE wallet_binding_requests ADD COLUMN age_leaf_commitment TEXT;
