-- Migration 038: iM8 wallet relay (CD-14)
--
-- wallet_binding_requests: PARA asks the iM8 wallet to bind a holder key for
-- an INE issuance. The wallet generates the key on the device and posts only
-- the public key and a proof of possession over the snapshotted issuance
-- challenge; the issued credentials wait here for the wallet to collect them
-- once, so PARA never holds them. Rows expire with WALLET_BINDING_TTL_SEC.
--
-- identity_requests.result_json: the minimal verification result a requester
-- reads back after the wallet presented. Cleared on first read.

CREATE TABLE IF NOT EXISTS wallet_binding_requests (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  issuance_challenge TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  holder_public_key TEXT,
  credentials_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wallet_binding_requests_session
  ON wallet_binding_requests(session_id, status);

ALTER TABLE identity_requests ADD COLUMN result_json TEXT;
