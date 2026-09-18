-- F2b bridge (CRYPTO_DECISIONS.md CD-9): give an anonymous identity an optional
-- anchor to its registered public key, so it can be resolved by proof of
-- possession instead of by session.
--
-- Additive and reversible on purpose. The column is nullable and has NO foreign
-- key: it points at a key the client holds, verified by `registered_identities`
-- at write time, not at a row the server owns. Existing rows keep working
-- through `session_id` during the transition. Nothing is removed here — the
-- `session_id` FK is dropped only once every read resolves by key and the
-- dependent tables (posts, germ, follows) have re-anchored. Deleting it before
-- then would break the live anonymous surface.
ALTER TABLE anonymous_identities ADD COLUMN identity_pub TEXT;

-- One registered key anchors at most one anonymous identity. Partial unique
-- index so the many existing rows with NULL identity_pub are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS idx_anonymous_identities_pub
  ON anonymous_identities(identity_pub)
  WHERE identity_pub IS NOT NULL;
