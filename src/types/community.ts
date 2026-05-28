import { z } from 'zod'

export type CommunityStatus = 'pending_admins' | 'active' | 'dissolved'

export type CommunityMembershipStatus = 'pending' | 'active' | 'suspended' | 'left'

export type CommunityAdminStatus = 'active' | 'removed'

export type CommunityActionType =
  | 'blog_post'
  | 'ruleset_mod'
  | 'name_change'
  | 'compass_change'
  | 'manifesto_update'
  | 'admin_add'
  | 'admin_remove'

export type CommunityActionImpactLevel = 'low' | 'high'

export type CommunityActionStatus = 'pending' | 'approved' | 'rejected' | 'executed' | 'failed'

export type CommunityActionVote = 'approve' | 'reject'

export type Community = {
  id: string
  did: string
  handle: string | null
  name: string
  description: string
  manifestoCid: string | null
  politicalCompassX: number | null
  politicalCompassY: number | null
  rulesetCid: string | null
  pdsHost: string
  status: CommunityStatus
  createdByDid: string
  bootstrapUsedAt: string | null
  createdAt: string
  updatedAt: string
}

export type CommunityAdmin = {
  communityId: string
  adminDid: string
  addedByDid: string | null
  addedAt: string
  status: CommunityAdminStatus
}

export type CommunityMembership = {
  communityId: string
  memberDid: string
  status: CommunityMembershipStatus
  membershipRecordUri: string | null
  groupRecordUri: string | null
  joinedAt: string | null
  leftAt: string | null
}

export type CommunityAction = {
  id: string
  communityId: string
  actionType: CommunityActionType
  impactLevel: CommunityActionImpactLevel
  payload: Record<string, unknown>
  proposedByDid: string
  status: CommunityActionStatus
  requiredApprovals: number
  currentApprovals: number
  repoCommitCid: string | null
  createdAt: string
  executedAt: string | null
  failedReason: string | null
}

export type CommunityActionVoteRecord = {
  actionId: string
  adminDid: string
  vote: CommunityActionVote
  voteSignature: string
  signedAt: string | null
  signedPayloadHash: string | null
  verificationMethodId: string | null
  signatureNonce: string | null
  votedAt: string
}

export const COMMUNITY_ACTION_THRESHOLDS: Record<
  CommunityActionType,
  { impact: CommunityActionImpactLevel; required: number }
> = {
  blog_post: { impact: 'low', required: 2 },
  ruleset_mod: { impact: 'low', required: 2 },
  name_change: { impact: 'high', required: 3 },
  compass_change: { impact: 'high', required: 3 },
  manifesto_update: { impact: 'high', required: 3 },
  admin_add: { impact: 'high', required: 3 },
  admin_remove: { impact: 'high', required: 3 },
}

export const MIN_COMMUNITY_ADMINS = 3

export const CreateCommunityInputSchema = z
  .object({
    did: z.string().min(1),
    handle: z.string().min(1).optional(),
    name: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    pdsHost: z.string().min(1).optional(),
  })
  .strict()

export type CreateCommunityInput = z.infer<typeof CreateCommunityInputSchema>

export const ProposeActionInputSchema = z
  .object({
    actionType: z.enum([
      'blog_post',
      'ruleset_mod',
      'name_change',
      'compass_change',
      'manifesto_update',
      'admin_add',
      'admin_remove',
    ]),
    payload: z.record(z.unknown()),
  })
  .strict()

export type ProposeActionInput = z.infer<typeof ProposeActionInputSchema>

export const VoteActionInputSchema = z
  .object({
    vote: z.enum(['approve', 'reject']),
    signature: z.string().min(1),
    signedAt: z.string().datetime(),
    nonce: z.string().min(16).max(256),
    keyId: z.string().min(1).max(512).optional(),
  })
  .strict()

export type VoteActionInput = z.infer<typeof VoteActionInputSchema>

export const AddAdminInputSchema = z
  .object({
    adminDid: z.string().min(1),
  })
  .strict()

export type AddAdminInput = z.infer<typeof AddAdminInputSchema>

export const BootstrapAdminsInputSchema = z
  .object({
    adminDids: z.array(z.string().min(1)).min(1).max(20),
  })
  .strict()

export type BootstrapAdminsInput = z.infer<typeof BootstrapAdminsInputSchema>
