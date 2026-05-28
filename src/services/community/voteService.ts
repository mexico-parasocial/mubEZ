import { getDb } from '../../db/connection.js'
import type { CommunityAction, CommunityActionVote, CommunityActionStatus } from '../../types/index.js'
import { verifyCommunityVoteSignature } from '../communityVoteSignatureService.js'
import { assertIsAdmin, getAdminCount } from '../communityAdminService.js'
import { appError } from '../../utils/errors.js'
import { nowIso } from '../../utils/time.js'
import { mapAction } from './mappers.js'
import { executeApprovedAction } from './actionExecutor.js'

export async function voteOnAction(
  actionId: string,
  adminDid: string,
  vote: CommunityActionVote,
  signature: string,
  signedAt: string,
  nonce: string,
  keyId?: string
): Promise<{ action: CommunityAction; executed: boolean }> {
  const db = getDb()
  const now = nowIso()

  const actionRow = db.prepare('SELECT * FROM community_actions WHERE id = ?').get(actionId) as
    | Record<string, unknown>
    | undefined
  if (!actionRow) {
    throw appError('Action not found', 404, 'ACTION_NOT_FOUND')
  }

  const action = mapAction(actionRow)

  if (action.status !== 'pending') {
    throw appError(`Action is already ${action.status}`, 409, 'ACTION_NOT_PENDING')
  }

  assertIsAdmin(action.communityId, adminDid)

  const verification = await verifyCommunityVoteSignature({
    action,
    adminDid,
    vote,
    signature,
    signedAt,
    nonce,
    keyId,
  })

  // Check if already voted
  const existingVote = db
    .prepare('SELECT 1 FROM community_action_votes WHERE action_id = ? AND admin_did = ?')
    .get(actionId, adminDid) as Record<string, unknown> | undefined

  if (existingVote) {
    throw appError('You have already voted on this action', 409, 'ALREADY_VOTED')
  }

  let newStatus: CommunityActionStatus = 'pending'
  let newApprovalCount = 0
  let shouldExecute = false

  try {
    db.transaction(() => {
      db.prepare(`
        INSERT INTO community_action_votes
          (action_id, admin_did, vote, vote_signature, signed_at, signed_payload_hash, verification_method_id, signature_nonce, voted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        actionId,
        adminDid,
        vote,
        signature,
        verification.payload.signedAt,
        verification.signedPayloadHash,
        verification.verificationMethodId,
        verification.payload.nonce,
        now
      )

      const approvalCount = db
        .prepare(
          "SELECT COUNT(*) as count FROM community_action_votes WHERE action_id = ? AND vote = 'approve'"
        )
        .get(actionId) as Record<string, unknown>
      newApprovalCount = approvalCount.count as number

      const rejectionCount = db
        .prepare(
          "SELECT COUNT(*) as count FROM community_action_votes WHERE action_id = ? AND vote = 'reject'"
        )
        .get(actionId) as Record<string, unknown>
      const newRejectionCount = rejectionCount.count as number

      const adminCount = getAdminCount(action.communityId)

      if (newApprovalCount >= action.requiredApprovals) {
        newStatus = 'approved'
        shouldExecute = true
      } else if (newRejectionCount > adminCount - action.requiredApprovals) {
        newStatus = 'rejected'
      }

      db.prepare(
        'UPDATE community_actions SET status = ?, current_approvals = ? WHERE id = ?'
      ).run(newStatus, newApprovalCount, actionId)
    })()
  } catch (error) {
    if (error instanceof Error && error.message.includes('UNIQUE constraint failed: community_action_votes.signature_nonce')) {
      throw appError('Vote signature nonce has already been used', 409, 'SIGNATURE_NONCE_REUSED')
    }
    throw error
  }

  action.status = newStatus
  action.currentApprovals = newApprovalCount

  let executed = false
  if (shouldExecute) {
    executed = await executeApprovedAction(action)
  }

  return { action, executed }
}
