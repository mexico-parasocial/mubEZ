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
import {
  followAnonymousProfile,
  getAnonymousProfilePublic,
  unfollowAnonymousProfile,
} from '../../src/services/anonymousFollowService.js'
import { Features, assertDemoPathAllowed } from '../../src/services/features.js'
import { verifyAnonymousActionProof } from '../../src/services/anonymousActionProof.js'

const surfaceSchema = z.enum(['public', 'civic', 'dating'])

// F2b / CD-10: an optional per-request proof of possession of the anonymous
// identity key. When present it authorizes the mutation by key rather than only
// by session, and anchors the row to that key. Optional during the additive
// transition; the session path still works when it is absent.
const hex = (bytes: number) =>
  z.string().regex(new RegExp(`^[0-9a-f]{${bytes * 2}}$`), `expected ${bytes}-byte hex`)
const actionProofSchema = z
  .object({
    signed: z
      .object({
        assertion: z
          .object({
            type: z.literal('para.identity.pop.v1'),
            purpose: z.literal('anon-action'),
            audience: z.string().min(1).max(256),
            identityPub: hex(32),
            challenge: z.string().min(1).max(512),
            signedAt: z.string().min(1).max(64),
          })
          .strict(),
        signature: hex(64),
      })
      .strict(),
    jti: z.string().min(1).max(256),
  })
  .strict()

const createIdentitySchema = z
  .object({
    displayName: z.string().min(1).max(80).optional(),
    surface: surfaceSchema.optional(),
    communityUri: z.string().min(1).max(512).nullable().optional(),
    burnAfter: z.enum(['none', 'post']).optional(),
    proof: actionProofSchema.optional(),
  })
  .strict()

const updateIdentitySchema = z
  .object({
    displayName: z.string().min(1).max(80).optional(),
    status: z.enum(['active', 'archived']).optional(),
    burnAfter: z.enum(['none', 'post']).optional(),
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

    // F2b / CD-10: if the client proves possession of its anonymous key, verify
    // the proof and anchor the new row to that key. A bad proof is rejected
    // rather than falling back to the session path — a caller that sends a proof
    // is asserting a key, and we do not silently ignore a failed assertion.
    const { proof, ...input } = body
    let identityPub: string | undefined
    if (proof) {
      const result = verifyAnonymousActionProof({
        signed: proof.signed,
        jti: proof.jti,
        action: 'create',
      })
      if (!result.ok) {
        return ctx.response.status(401).send({ error: 'Invalid identity proof' })
      }
      identityPub = result.identityPub
    }

    return ctx.response
      .status(201)
      .send({ identity: createAnonymousIdentity(sessionId, { ...input, identityPub }) })
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
    const result = linkAnonymousPost(sessionId, body)
    return ctx.response.status(201).send({ post: result.post, rotatedIdentity: result.rotatedIdentity })
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

  async showProfile(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send(getAnonymousProfilePublic(sessionId, ctx.params.id))
  }

  async followProfile(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send(followAnonymousProfile(sessionId, ctx.params.id))
  }

  async unfollowProfile(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send(unfollowAnonymousProfile(sessionId, ctx.params.id))
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
