-- Optional PKCE S256 binding for PARA's native and web handoffs.
-- Legacy clients retain their existing exchange contract during rollout.
ALTER TABLE oauth_login_attempts ADD COLUMN exchange_challenge TEXT NULL;
