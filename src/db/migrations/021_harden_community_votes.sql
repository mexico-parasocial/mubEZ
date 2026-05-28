-- Migration 021: Harden community governance votes

ALTER TABLE communities ADD COLUMN bootstrap_used_at TEXT;

ALTER TABLE community_action_votes ADD COLUMN signed_at TEXT;
ALTER TABLE community_action_votes ADD COLUMN signed_payload_hash TEXT;
ALTER TABLE community_action_votes ADD COLUMN verification_method_id TEXT;
ALTER TABLE community_action_votes ADD COLUMN signature_nonce TEXT;

-- Closed beta safety: pre-hardening votes were stored but not cryptographically
-- verified. They must not be counted after the verifier is introduced.
DELETE FROM community_action_votes;

UPDATE community_actions
SET current_approvals = 0,
    status = CASE
      WHEN status IN ('approved', 'rejected') THEN 'pending'
      ELSE status
    END
WHERE id IN (SELECT id FROM community_actions);

CREATE UNIQUE INDEX IF NOT EXISTS ux_community_action_votes_nonce
ON community_action_votes(signature_nonce)
WHERE signature_nonce IS NOT NULL;
