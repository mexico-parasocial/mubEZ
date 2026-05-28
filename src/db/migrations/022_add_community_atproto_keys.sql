-- Migration 022: Add ATProto-compatible community service auth keys

ALTER TABLE communities ADD COLUMN community_atproto_key_public_multibase TEXT;
ALTER TABLE communities ADD COLUMN community_atproto_key_private_jwk TEXT;
ALTER TABLE communities ADD COLUMN community_atproto_key_type TEXT;
ALTER TABLE communities ADD COLUMN community_atproto_key_id TEXT;

CREATE INDEX IF NOT EXISTS idx_communities_atproto_key_id
ON communities(community_atproto_key_id)
WHERE community_atproto_key_id IS NOT NULL;
