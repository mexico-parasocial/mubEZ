-- F2b — the standalone identity registry (CRYPTO_DECISIONS.md CD-9).
--
-- A PARA identity is registered by its public key with a proof of possession.
-- Each key is stored ALONE: there is deliberately no session_id, no seed, no
-- view key, and no reference to another identity's key on this table. That
-- absence is the guarantee (IDENTITY_DERIVATION.md: "No table may relate two
-- identity public keys, or an identity key to a seed, view key, or another
-- identity's session"), and tests/unit/identity-registration.test.ts fails if a
-- later migration adds such a column or a foreign key here.
CREATE TABLE IF NOT EXISTS registered_identities (
  identity_pub TEXT PRIMARY KEY,          -- 32-byte sr25519 public key, hex
  registered_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Registration challenges are anonymous and single-use. They are keyed by the
-- challenge value itself, NOT by a session and NOT by the identity that will
-- consume them: binding a challenge to a session before registration would
-- recreate the session<->identity linkage this whole contract removes, and
-- binding it to an identity_pub would let an observer correlate challenge
-- issuance with the key that later registers. A challenge is issued blind,
-- signed over by whoever holds the key, and consumed on the first valid proof.
CREATE TABLE IF NOT EXISTS identity_registration_challenges (
  challenge TEXT PRIMARY KEY,             -- 256-bit random nonce, base64url
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  consumed_at TEXT
);
