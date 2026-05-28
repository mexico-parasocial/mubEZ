CREATE TABLE IF NOT EXISTS chat_key_backups (
  session_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  encryption_metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
