import type {
  Community,
  CommunityStatus,
  CommunityAdmin,
  CommunityAdminStatus,
  CommunityMembership,
  CommunityMembershipStatus,
  CommunityAction,
  CommunityActionStatus,
  CommunityActionType,
  CommunityActionVote,
  CommunityActionVoteRecord,
} from '../../types/index.js'

export function mapCommunity(row: Record<string, unknown>): Community {
  return {
    id: row.id as string,
    did: row.did as string,
    handle: (row.handle as string) ?? null,
    name: row.name as string,
    description: row.description as string,
    manifestoCid: (row.manifesto_cid as string) ?? null,
    politicalCompassX: (row.political_compass_x as number) ?? null,
    politicalCompassY: (row.political_compass_y as number) ?? null,
    rulesetCid: (row.ruleset_cid as string) ?? null,
    pdsHost: (row.pds_host as string) || '',
    status: row.status as CommunityStatus,
    createdByDid: row.created_by_did as string,
    bootstrapUsedAt: (row.bootstrap_used_at as string) ?? null,
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  }
}

export function mapAdmin(row: Record<string, unknown>): CommunityAdmin {
  return {
    communityId: row.community_id as string,
    adminDid: row.admin_did as string,
    addedByDid: (row.added_by_did as string) ?? null,
    addedAt: row.added_at as string,
    status: row.status as CommunityAdminStatus,
  }
}

export function mapAction(row: Record<string, unknown>): CommunityAction {
  return {
    id: row.id as string,
    communityId: row.community_id as string,
    actionType: row.action_type as CommunityActionType,
    impactLevel: row.impact_level as 'low' | 'high',
    payload: JSON.parse((row.payload as string) || '{}'),
    proposedByDid: row.proposed_by_did as string,
    status: row.status as CommunityActionStatus,
    requiredApprovals: row.required_approvals as number,
    currentApprovals: row.current_approvals as number,
    repoCommitCid: (row.repo_commit_cid as string) ?? null,
    createdAt: row.created_at as string,
    executedAt: (row.executed_at as string) ?? null,
    failedReason: (row.failed_reason as string) ?? null,
  }
}

export function mapVote(row: Record<string, unknown>): CommunityActionVoteRecord {
  return {
    actionId: row.action_id as string,
    adminDid: row.admin_did as string,
    vote: row.vote as CommunityActionVote,
    voteSignature: row.vote_signature as string,
    signedAt: (row.signed_at as string) ?? null,
    signedPayloadHash: (row.signed_payload_hash as string) ?? null,
    verificationMethodId: (row.verification_method_id as string) ?? null,
    signatureNonce: (row.signature_nonce as string) ?? null,
    votedAt: row.voted_at as string,
  }
}

export function mapMembership(row: Record<string, unknown>): CommunityMembership {
  return {
    communityId: row.community_id as string,
    memberDid: row.member_did as string,
    status: row.status as CommunityMembershipStatus,
    membershipRecordUri: (row.membership_record_uri as string) ?? null,
    groupRecordUri: (row.group_record_uri as string) ?? null,
    joinedAt: (row.joined_at as string) ?? null,
    leftAt: (row.left_at as string) ?? null,
  }
}
