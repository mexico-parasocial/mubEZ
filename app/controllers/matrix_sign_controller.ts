import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  createMatrixSignRequest,
  fulfillMatrixSignRequest,
  getMatrixSignRequest,
  listPendingMatrixSignRequests,
} from '../../src/services/matrixSignService.js'

const createSchema = z
  .object({
    challenge: z.string(),
    audience: z.enum([
      'para-matrix-bridge/identity.v1',
      'para-matrix-bridge/session.v1',
      'para-matrix-bridge/attest.v1',
      'para-matrix-bridge/join.v1',
      'para-idp',
    ]),
  })
  .refine(
    (input) =>
      input.audience === 'para-idp'
        ? /^[A-Za-z0-9_-]{43}$/.test(input.challenge)
        : /^[0-9a-f]{64}$/.test(input.challenge),
    { message: 'Invalid Matrix challenge', path: ['challenge'] },
  )

const fulfillSchema = z.object({
  assertion: z.object({
    type: z.literal('para.identity.pop.v1'),
    purpose: z.literal('matrix-login'),
    audience: z.string(),
    identityPub: z.string(),
    challenge: z.string(),
    signedAt: z.string(),
  }),
  signature: z.string().regex(/^[0-9a-f]{128}$/, 'signature must be 128 hex chars'),
})

/**
 * Session-bound relay between PARA (requests a signature) and the iM8
 * wallet (signs after user approval). See matrixSignService.ts.
 */
export default class MatrixSignController {
  async store(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, createSchema)
    if (!body) return
    return ctx.response.status(201).send(createMatrixSignRequest(sessionId, body))
  }

  /** Pending list for the wallet's approval surface. */
  async index(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send({
      requests: listPendingMatrixSignRequests(sessionId),
    })
  }

  /** PARA's poll: pending until the wallet fulfills it. */
  async show(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const request = getMatrixSignRequest(sessionId, ctx.params.id)
    if (!request) {
      return ctx.response.notFound({
        error: 'Sign request not found or expired',
      })
    }
    return ctx.response.send(request)
  }

  async fulfill(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, fulfillSchema)
    if (!body) return

    const result = fulfillMatrixSignRequest(sessionId, ctx.params.id, body)
    if (!result.ok) {
      const status = result.reason === 'not-found' ? 404 : 400
      return ctx.response.status(status).send({ error: result.reason })
    }
    return ctx.response.send({ status: 'fulfilled' })
  }
}
