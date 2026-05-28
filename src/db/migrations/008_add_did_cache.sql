CREATE TABLE IF NOT EXISTS did_cache (
  did TEXT PRIMARY KEY,
  doc TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL DEFAULT (datetime('now', '+1 hour'))
);

CREATE INDEX IF NOT EXISTS idx_did_cache_expires ON did_cache(expires_at);
