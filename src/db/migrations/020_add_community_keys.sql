-- Migration 020: Add community signing keys and PDS auth

ALTER TABLE communities ADD COLUMN signing_key_public TEXT;
ALTER TABLE communities ADD COLUMN signing_key_private TEXT;
ALTER TABLE communities ADD COLUMN pds_auth_token TEXT;
