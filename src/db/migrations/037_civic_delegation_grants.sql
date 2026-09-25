CREATE TABLE IF NOT EXISTS civic_delegation_grants (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL REFERENCES person_roots(id) ON DELETE CASCADE,
  issued_at TEXT NOT NULL DEFAULT (datetime('now'))
);
