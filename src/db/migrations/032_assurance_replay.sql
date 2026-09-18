-- CD-10: the shared replay-consume primitive for the broker.
--
-- One implementation, used by both assurance roles mubEZ owns (the anon-action
-- PoP verifier now; the assurance-JWT issuer later). It mirrors the reviewed PDS
-- primitive (WatZappa-permissioned-data .../m8-assurance-store): a server-issued
-- single-use challenge plus a one-time id (jti), consumed atomically so a replay
-- fails even under a race, and a jti can never spend a second nonce.
--
-- Neither table carries a session id: challenges are keyed by the hash of the
-- nonce and bound to the request by a binding hash, never to a session.

CREATE TABLE IF NOT EXISTS assurance_challenge (
  nonce_hash    TEXT PRIMARY KEY,        -- sha256(nonce) hex; the raw nonce is returned once, never stored
  subject       TEXT NOT NULL,           -- identity/subject the pending-count cap is scoped to
  binding_hash  TEXT NOT NULL,           -- sha256 of the canonical bindings this nonce is issued for
  issuer        TEXT NOT NULL,
  issued_at     INTEGER NOT NULL,        -- unix seconds
  expires_at    INTEGER NOT NULL,        -- unix seconds
  consumed_at   INTEGER                  -- null until spent
);
CREATE INDEX IF NOT EXISTS idx_assurance_challenge_subject ON assurance_challenge(subject, expires_at);
CREATE INDEX IF NOT EXISTS idx_assurance_challenge_expiry ON assurance_challenge(expires_at);

-- Independent of the challenge: one jti cannot spend a second nonce.
CREATE TABLE IF NOT EXISTS assurance_receipt (
  issuer        TEXT NOT NULL,
  jti_hash      TEXT NOT NULL,           -- sha256(jti) hex
  consumed_at   INTEGER NOT NULL,
  retain_until  INTEGER NOT NULL,
  PRIMARY KEY (issuer, jti_hash)
);
CREATE INDEX IF NOT EXISTS idx_assurance_receipt_expiry ON assurance_receipt(retain_until);
