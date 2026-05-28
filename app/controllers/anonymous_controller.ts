import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  createAnonymousIdentity,
  getAnonymousContactEligibility,
  getAnonymousPublicContact,
  linkAnonymousPost,
  linkGermContact,
  listAnonymousIdentities,
  unlinkGermContact,
  updateAnonymousIdentity,
  updateAnonymousPostDmPolicy,
  updateAnonymousPostStats,
} from '../../src/services/anonymousIdentityService.js'
import { getDeviceTrustSummary, upsertDevelopmentTrustedDevice } from '../../src/services/deviceTrustService.js'
import { Features, assertDemoPathAllowed } from '../../src/services/features.js'

const surfaceSchema = z.enum(['public', 'civic', 'dating'])

const createIdentitySchema = z
  .object({
    displayName: z.string().min(1).max(80).optional(),
    surface: surfaceSchema.optional(),
    communityUri: z.string().min(1).max(512).nullable().optional(),
  })
  .strict()

const updateIdentitySchema = z
  .object({
    displayName: z.string().min(1).max(80).optional(),
    status: z.enum(['active', 'archived']).optional(),
  })
  .strict()

const linkPostSchema = z
  .object({
    identityId: z.string().min(1).optional(),
    postUri: z.string().min(1).max(512),
    communityUri: z.string().min(1).max(512).nullable().optional(),
    postType: z.string().min(1).max(40).optional(),
    stats: z
      .object({
        replyCount: z.number().int().min(0).optional(),
        repostCount: z.number().int().min(0).optional(),
        likeCount: z.number().int().min(0).optional(),
        quoteCount: z.number().int().min(0).optional(),
        threadCount: z.number().int().min(0).optional(),
      })
      .strict()
      .optional(),
  })
  .strict()

const dmPolicySchema = z
  .object({
    dmPolicy: z.enum(['off', 'requests', 'para-verified']),
  })
  .strict()

const postStatsSchema = z
  .object({
    replyCount: z.number().int().min(0).optional(),
    repostCount: z.number().int().min(0).optional(),
    likeCount: z.number().int().min(0).optional(),
    quoteCount: z.number().int().min(0).optional(),
    threadCount: z.number().int().min(0).optional(),
  })
  .strict()

const germLinkSchema = z
  .object({
    contactUrl: z.string().url().max(2047),
    providerRef: z.string().max(512).optional(),
    mode: z.enum(['germ-card-link', 'm8-relay-pending-germ']).optional(),
  })
  .strict()

const devTrustSchema = z
  .object({
    platform: z.enum(['ios', 'android', 'web']),
    deviceKeyId: z.string().min(1).max(256),
    publicKey: z.string().max(4096).optional(),
  })
  .strict()

export default class AnonymousController {
  async identities(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send({ identities: listAnonymousIdentities(sessionId) })
  }

  async createIdentity(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, createIdentitySchema)
    if (!body) return
    return ctx.response.status(201).send({ identity: createAnonymousIdentity(sessionId, body) })
  }

  async updateIdentity(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, updateIdentitySchema)
    if (!body) return
    return ctx.response.send({ identity: updateAnonymousIdentity(sessionId, ctx.params.id, body) })
  }

  async linkPost(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, linkPostSchema)
    if (!body) return
    return ctx.response.status(201).send({ post: linkAnonymousPost(sessionId, body) })
  }

  async updatePostDmPolicy(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, dmPolicySchema)
    if (!body) return
    return ctx.response.send({ post: updateAnonymousPostDmPolicy(sessionId, ctx.params.id, body.dmPolicy) })
  }

  async updatePostStats(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, postStatsSchema)
    if (!body) return
    return ctx.response.send({ post: updateAnonymousPostStats(sessionId, ctx.params.id, body) })
  }

  async linkGerm(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, germLinkSchema)
    if (!body) return
    return ctx.response.send({ germ: linkGermContact(sessionId, ctx.params.id, body) })
  }

  async unlinkGerm(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send({ germ: unlinkGermContact(sessionId, ctx.params.id) })
  }

  async publicContact(ctx: HttpContext) {
    const postUri = (ctx.request.qs() as { postUri?: string }).postUri
    if (!postUri) return ctx.response.status(400).send({ error: 'postUri is required' })
    return ctx.response.send(getAnonymousPublicContact(postUri))
  }

  async publicContactEligibility(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const postUri = (ctx.request.qs() as { postUri?: string }).postUri
    if (!postUri) return ctx.response.status(400).send({ error: 'postUri is required' })

    const result = getAnonymousContactEligibility(sessionId, postUri)
    return ctx.response.status(result.eligible ? 200 : 403).send(result)
  }

  async deviceTrust(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send({ deviceTrust: getDeviceTrustSummary(sessionId) })
  }

  async verifyDevelopmentDevice(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, devTrustSchema)
    if (!body) return
    if (!assertDemoPathAllowed(Features.DevelopmentDeviceTrustEnable)) {
      return ctx.response.status(404).send({
        error: 'Development device trust override is disabled',
        code: 'FEATURE_DISABLED',
      })
    }
    return ctx.response.send({ deviceTrust: upsertDevelopmentTrustedDevice(sessionId, body) })
  }
}
