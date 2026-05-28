import type { HttpContext } from '@adonisjs/core/http'
import { getSessionDid } from '#support/http'
import { getCommunity } from '../../../src/services/communityService.js'
import { isAdmin } from '../../../src/services/communityAdminService.js'
import {
  listMemberships,
  requestMembership,
  approveMembership,
  rejectMembership,
  leaveMembership,
  updateMembershipUris,
} from '../../../src/services/community/membershipService.js'
import { addCommunityMemberRecord } from '../../../src/services/community/repoSyncService.js'
import { xrpcRequest } from '../../../src/services/atprotoAgent.js'
import { appError } from '../../../src/utils/errors.js'
import { nowIso } from '../../../src/utils/time.js'

export default class CommunityMembershipsController {
  async index(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const status = ctx.request.qs().status as string | undefined
    const limit = Math.min(parseInt(ctx.request.qs().limit as string) || 50, 100)
    const offset = parseInt(ctx.request.qs().offset as string) || 0

    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    const result = listMemberships(communityId, {
      status: status as 'pending' | 'active' | 'suspended' | 'left' | undefined,
      limit,
      offset,
    })

    return ctx.response.send({
      memberships: result.memberships,
      pagination: { total: result.total, limit, offset },
    })
  }

  async store(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const memberDid = await getSessionDid(ctx)
    const now = nowIso()

    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    const membership = requestMembership(communityId, memberDid)

    // Write membership request to member's repo (first half of two-way handshake)
    let memberRecordUri: string | null = null
    try {
      const memberRecord = await xrpcRequest(memberDid, 'com.atproto.repo.createRecord', {
        method: 'POST',
        body: JSON.stringify({
          repo: memberDid,
          collection: 'app.m8.community.membership',
          record: {
            $type: 'app.m8.community.membership',
            communityDid: community.did,
            status: 'pending',
            joinedAt: now,
          },
        }),
      }) as { uri: string; cid: string }
      memberRecordUri = memberRecord.uri
      updateMembershipUris(communityId, memberDid, { membershipRecordUri: memberRecordUri })
    } catch {
      // Best-effort: member's PDS might not be accessible
    }

    return ctx.response.status(201).send({
      message: 'Membership request submitted. Awaiting admin approval.',
      membership: {
        ...membership,
        memberRecordUri,
      },
    })
  }

  async approve(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const memberDid = ctx.params.did as string
    const now = nowIso()

    const adminDid = await getSessionDid(ctx)
    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    if (!isAdmin(communityId, adminDid)) {
      throw appError('Only admins can approve memberships', 403, 'NOT_ADMIN')
    }

    const approved = approveMembership(communityId, memberDid)
    if (!approved) {
      throw appError('Pending membership not found', 404, 'MEMBERSHIP_NOT_FOUND')
    }

    // Two-way handshake: write member record to community's repo
    let groupRecordUri: string | null = null
    try {
      const groupRecord = await addCommunityMemberRecord(communityId, memberDid, now)
      groupRecordUri = groupRecord.uri
    } catch {
      // Best-effort: PDS sync failure shouldn't block membership approval
    }

    // Two-way handshake: write membership record to member's repo
    let memberRecordUri: string | null = null
    try {
      const memberRecord = await xrpcRequest(memberDid, 'com.atproto.repo.createRecord', {
        method: 'POST',
        body: JSON.stringify({
          repo: memberDid,
          collection: 'app.m8.community.membership',
          record: {
            $type: 'app.m8.community.membership',
            communityDid: community.did,
            status: 'active',
            joinedAt: now,
            ...(groupRecordUri ? { communityRecordUri: groupRecordUri } : {}),
          },
        }),
      }) as { uri: string; cid: string }
      memberRecordUri = memberRecord.uri
    } catch {
      // Best-effort: member's PDS might not be accessible
    }

    if (groupRecordUri || memberRecordUri) {
      updateMembershipUris(communityId, memberDid, { groupRecordUri, membershipRecordUri: memberRecordUri })
    }

    return ctx.response.send({
      message: 'Membership approved.',
      membership: {
        communityId,
        memberDid,
        status: 'active',
        joinedAt: now,
        groupRecordUri,
        memberRecordUri,
      },
    })
  }

  async reject(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const memberDid = ctx.params.did as string

    const adminDid = await getSessionDid(ctx)
    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    if (!isAdmin(communityId, adminDid)) {
      throw appError('Only admins can reject memberships', 403, 'NOT_ADMIN')
    }

    const rejected = rejectMembership(communityId, memberDid)
    if (!rejected) {
      throw appError('Pending membership not found', 404, 'MEMBERSHIP_NOT_FOUND')
    }

    return ctx.response.send({ message: 'Membership request rejected.' })
  }

  async leave(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const memberDid = await getSessionDid(ctx)

    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    const left = leaveMembership(communityId, memberDid)
    if (!left) {
      throw appError('Active membership not found', 404, 'MEMBERSHIP_NOT_FOUND')
    }

    return ctx.response.send({ message: 'You have left the community.' })
  }
}
