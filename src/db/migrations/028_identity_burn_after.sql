-- Burn-after lifecycle for isolated burner identities.
-- 'none' (default): identity persists. 'post': identity is archived after
-- each linked post and a fresh burner replaces it.
ALTER TABLE anonymous_identities ADD COLUMN burn_after TEXT NOT NULL DEFAULT 'none';
