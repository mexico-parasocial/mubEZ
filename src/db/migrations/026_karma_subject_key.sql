-- Server-derived karma: idempotency key per (profile, action, subject).
-- subject_key is assigned server-side from the action detail (e.g. vote:<subjectUri>).

ALTER TABLE karma ADD COLUMN subject_key TEXT NOT NULL DEFAULT '';

-- Collapse historical duplicates (all legacy rows share the empty subject_key)
-- so the uniqueness guarantee can be enforced.
DELETE FROM karma WHERE rowid NOT IN (
  SELECT MIN(rowid) FROM karma GROUP BY anonymous_profile_id, action_type, subject_key
);

CREATE UNIQUE INDEX IF NOT EXISTS karma_unique_action
  ON karma(anonymous_profile_id, action_type, subject_key);
