-- Per-session issuance challenge for credential replay protection.
-- See PARA_INTEGRATION_CONTRACT.md: challenges are single-use and rotated
-- after each credential issuance attempt.
ALTER TABLE sessions ADD COLUMN issuance_challenge TEXT;
