-- Migration 029: store the para.artifact.v1 attestation issued at creation.
-- Nullable: rows created before signing existed (or with no issuer seed
-- configured) simply have no attestation and verify as unsigned clientside.

ALTER TABLE proof_artifacts ADD COLUMN attestation_json TEXT;
