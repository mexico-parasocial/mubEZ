-- Migration 014: Database-level identity and token invariants

CREATE UNIQUE INDEX IF NOT EXISTS ux_proof_artifacts_active_commitment
ON proof_artifacts(commitment)
WHERE commitment IS NOT NULL
  AND status IN ('pending', 'active', 'suspended');

CREATE UNIQUE INDEX IF NOT EXISTS ux_proof_artifacts_revocation_hash
ON proof_artifacts(revocation_hash)
WHERE revocation_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_sessions_active_did
ON sessions(did)
WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS ux_refresh_tokens_replacement
ON refresh_tokens(replaced_by_token_hash)
WHERE replaced_by_token_hash IS NOT NULL;
