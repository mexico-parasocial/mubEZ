-- Migration 002: Add revocation and ZKP commitment tracking to proof_artifacts

ALTER TABLE proof_artifacts ADD COLUMN revocation_hash TEXT;
ALTER TABLE proof_artifacts ADD COLUMN commitment TEXT;

CREATE INDEX IF NOT EXISTS idx_proof_artifacts_revocation_hash ON proof_artifacts(revocation_hash);
CREATE INDEX IF NOT EXISTS idx_proof_artifacts_commitment ON proof_artifacts(commitment);
