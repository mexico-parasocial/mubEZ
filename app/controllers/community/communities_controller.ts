import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, getSessionDid, validateBody } from '#support/http'
import { appError } from '../../../src/utils/errors.js'
import {
  createCommunity,
  getCommunity,
  listCommunities,
} from '../../../src/services/communityService.js'
import {
  listAdmins,
  getAdminCount,
  bootstrapCommunityAdmins,
} from '../../../src/services/communityAdminService.js'
import { proposeAction } from '../../../src/services/community/actionService.js'
import { CreateCommunityInputSchema, AddAdminInputSchema, BootstrapAdminsInputSchema } from '../../../src/types/index.js'



export default class CommunitiesController {
  async index(ctx: HttpContext) {
    const status = ctx.request.qs().status as string | undefined
    const limit = Math.min(parseInt(ctx.request.qs().limit as string) || 50, 100)
    const offset = parseInt(ctx.request.qs().offset as string) || 0

    const result = listCommunities({
      status: status as 'pending_admins' | 'active' | 'dissolved' | undefined,
      limit,
      offset,
    })

    return ctx.response.send({
      communities: result.communities,
      pagination: { total: result.total, limit, offset },
    })
  }

  async show(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    const admins = listAdmins(communityId)
    const adminCount = getAdminCount(communityId)

    return ctx.response.send({
      community,
      admins: admins.filter((a) => a.status === 'active'),
      adminCount,
      isPendingActivation: community.status === 'pending_admins',
    })
  }

  async store(ctx: HttpContext) {
    const body = validateBody(ctx, CreateCommunityInputSchema)
    if (!body) return

    const sessionId = getSessionId(ctx)
    const community = createCommunity(sessionId, body)

    return ctx.response.status(201).send({ community })
  }

  async admins(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    const admins = listAdmins(communityId)
    return ctx.response.send({ admins })
  }

  async bootstrapAdmins(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const body = validateBody(ctx, BootstrapAdminsInputSchema)
    if (!body) return

    const requestedByDid = await getSessionDid(ctx)
    const result = bootstrapCommunityAdmins(communityId, requestedByDid, body.adminDids)
    const community = getCommunity(communityId)

    return ctx.response.status(200).send({
      message: 'Community admin bootstrap completed. Future admin changes require governance.',
      community,
      admins: result.admins,
    })
  }

  async addAdmin(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const body = validateBody(ctx, AddAdminInputSchema)
    if (!body) return

    const proposedByDid = await getSessionDid(ctx)
    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    // Adding an admin is a high-impact action that requires governance approval
    const action = proposeAction(communityId, proposedByDid, 'admin_add', {
      adminDid: body.adminDid,
    })

    return ctx.response.status(202).send({
      message: 'Admin addition proposed. Awaiting approval from other admins.',
      action,
    })
  }

  async removeAdmin(ctx: HttpContext) {
    const communityId = ctx.params.id as string
    const adminDid = ctx.params.did as string

    const proposedByDid = await getSessionDid(ctx)
    const community = getCommunity(communityId)
    if (!community) {
      throw appError('Community not found', 404, 'COMMUNITY_NOT_FOUND')
    }

    // Removing an admin is a high-impact action that requires governance approval
    const action = proposeAction(communityId, proposedByDid, 'admin_remove', {
      adminDid,
    })

    return ctx.response.status(202).send({
      message: 'Admin removal proposed. Awaiting approval from other admins.',
      action,
    })
  }
}
