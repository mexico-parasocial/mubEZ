-- Preserve the verifier requirement independently of OAuth audit-row cleanup.
ALTER TABLE oauth_exchange_codes ADD COLUMN exchange_challenge TEXT NULL;

UPDATE oauth_exchange_codes
SET exchange_challenge = (
  SELECT exchange_challenge FROM oauth_login_attempts
  WHERE oauth_login_attempts.id = oauth_exchange_codes.attempt_id
);

-- An outstanding code without its prior audit row cannot be safely backfilled.
UPDATE oauth_exchange_codes SET used_at = datetime('now')
WHERE used_at IS NULL AND NOT EXISTS (
  SELECT 1 FROM oauth_login_attempts
  WHERE oauth_login_attempts.id = oauth_exchange_codes.attempt_id
);
