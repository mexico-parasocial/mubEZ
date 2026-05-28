-- Add oauth_scope to sessions for scope-tier tracking
ALTER TABLE sessions ADD COLUMN oauth_scope TEXT NOT NULL DEFAULT 'atproto';

-- Add scope to oauth_login_attempts for audit trail
ALTER TABLE oauth_login_attempts ADD COLUMN scope TEXT NOT NULL DEFAULT 'atproto';
