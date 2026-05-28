-- Migration 009: Add proof artifact versioning columns
ALTER TABLE proof_artifacts ADD COLUMN proof_schema_version TEXT NOT NULL DEFAULT '1.0.0';
ALTER TABLE proof_artifacts ADD COLUMN circuit_id TEXT NOT NULL DEFAULT 'ine_age_proof_v1';
