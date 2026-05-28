import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import { approveGrant, requestGrant, revokeGrant } from '../../src/services/grantService.js'
import { hydrateSession } from '../../src/services/sessionService.js'
import { PROOF_BROKER_CLAIM_TYPES } from '../../src/types/index.js'

const claimSpecSchema = z.object({
  type: z.enum(PROOF_BROKER_CLAIM_TYPES),
  disclosure: z.enum(['proof-only', 'signed-claim', 'raw']),
  requestedValue: z.string().optional(),
})

const requestGrantSchema = z.object({
  appId: z.string().min(1).max(128),
  appName: z.string().min(1).max(256),
  appKind: z.enum(['Consumer app', 'Civic app', 'Community app', 'Local app', 'Verifier', 'Broker']),
  surface: z.enum(['public', 'civic', 'dating']),
  requestedClaims: z.array(claimSpecSchema).min(1).max(20),
  proofMode: z.enum(['proof-only', 'signed-claim', 'raw']),
  reason: z.string().min(1).max(1024),
  expiresAt: z.string().datetime().optional().nullable(),
})

const approveGrantSchema = z.object({
  reviewNote: z.string().max(2048).optional(),
  expiresAt: z.string().datetime().optional().nullable(),
})

const revokeGrantSchema = z.object({
  reason: z.string().max(2048).optional(),
})

export default class GrantsController {
  async index(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const session = hydrateSession(sessionId)
    return ctx.response.send({ grants: session.grants, proofs: session.proofs })
  }

  async store(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, requestGrantSchema)
    if (!body) return

    return ctx.response.status(201).send(requestGrant(sessionId, body))
  }

  async approve(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, approveGrantSchema)
    if (!body) return

    return ctx.response.send(approveGrant(sessionId, { ...body, grantId: ctx.params.id }))
  }

  async revoke(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, revokeGrantSchema)
    if (!body) return

    return ctx.response.send(revokeGrant(sessionId, { ...body, grantId: ctx.params.id }))
  }
}
