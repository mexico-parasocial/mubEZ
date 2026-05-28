import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { createIdentityRequest, createDemoWalletPresentation, verifyWalletPresentation } from '../../src/services/identityWallet.js'
import { hydrateSession } from '../../src/services/sessionService.js'
import { Features, assertDemoPathAllowed } from '../../src/services/features.js'
import { getSessionId, validateBody } from '#support/http'

const identityRequestSchema = z.object({
  audienceAppId: z.string().min(1),
  audienceAppName: z.string().min(1),
  purpose: z.string().min(1),
  merchantIdentifier: z.string().optional(),
  requestedElements: z.array(z.object({
    id: z.enum(['age_over_18', 'age_over_21', 'citizenship', 'district_hash', 'curp_hash', 'verified_public_figure']),
    intentToStore: z.union([
      z.object({ mode: z.literal('will-not-store') }),
      z.object({ mode: z.literal('may-store'), days: z.number().int().positive() }),
      z.object({ mode: z.literal('may-store-until-revoked') }),
    ]),
    required: z.boolean(),
  })).min(1),
  expiresInSeconds: z.number().int().min(30).max(900).optional(),
})

const presentationSchema = z.object({
  requestId: z.string().min(1),
  subjectDid: z.string().min(1),
  selectedElementIds: z.array(z.string()).optional(),
})

const verifyPresentationSchema = z.object({
  requestId: z.string().min(1),
  presentation: z.record(z.unknown()),
})

export default class IdentityWalletController {
  async request(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, identityRequestSchema)
    if (!body) return

    const req = createIdentityRequest(sessionId, body)
    const db = getDb()
    db.prepare(`
      INSERT INTO identity_requests (id, session_id, nonce, audience_app_id, audience_app_name, purpose, merchant_identifier, requested_elements_json, status, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.id, req.sessionId, req.nonce, req.audienceAppId, req.audienceAppName, req.purpose, req.merchantIdentifier, JSON.stringify(req.requestedElements), req.status, req.createdAt, req.expiresAt)

    return ctx.response.status(201).send(req)
  }

  async present(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, presentationSchema)
    if (!body) return
    if (!assertDemoPathAllowed(Features.DemoIdentityWalletEnable)) {
      return ctx.response.status(404).send({
        error: 'Demo identity wallet is disabled',
        code: 'FEATURE_DISABLED',
      })
    }

    const db = getDb()
    const row = db.prepare('SELECT * FROM identity_requests WHERE id = ? AND session_id = ?').get(body.requestId, sessionId) as Record<string, unknown> | undefined
    if (!row) {
      return ctx.response.status(404).send({ error: 'Identity request not found' })
    }

    const identityRequest = {
      id: row.id as string,
      sessionId: row.session_id as string,
      nonce: row.nonce as string,
      audienceAppId: row.audience_app_id as string,
      audienceAppName: row.audience_app_name as string,
      purpose: row.purpose as string,
      merchantIdentifier: row.merchant_identifier as string,
      requestedElements: JSON.parse(row.requested_elements_json as string),
      status: row.status as 'active' | 'used' | 'expired',
      createdAt: row.created_at as string,
      expiresAt: row.expires_at as string,
      usedAt: row.used_at as string | null,
    }

    const session = hydrateSession(sessionId)
    const presentation = createDemoWalletPresentation({
      request: identityRequest,
      subjectDid: session.did,
      selectedElementIds: body.selectedElementIds as Array<'age_over_18' | 'age_over_21' | 'citizenship' | 'district_hash' | 'curp_hash' | 'verified_public_figure'>,
    })

    return ctx.response.send(presentation)
  }

  async verify(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, verifyPresentationSchema)
    if (!body) return

    const db = getDb()
    const row = db.prepare('SELECT * FROM identity_requests WHERE id = ? AND session_id = ?').get(body.requestId, sessionId) as Record<string, unknown> | undefined
    if (!row) {
      return ctx.response.status(404).send({ error: 'Identity request not found' })
    }

    const identityRequest = {
      id: row.id as string,
      sessionId: row.session_id as string,
      nonce: row.nonce as string,
      audienceAppId: row.audience_app_id as string,
      audienceAppName: row.audience_app_name as string,
      purpose: row.purpose as string,
      merchantIdentifier: row.merchant_identifier as string,
      requestedElements: JSON.parse(row.requested_elements_json as string),
      status: row.status as 'active' | 'used' | 'expired',
      createdAt: row.created_at as string,
      expiresAt: row.expires_at as string,
      usedAt: row.used_at as string | null,
    }

    const presentation = body.presentation as import('../../src/types/index.js').M8WalletPresentation
    const result = verifyWalletPresentation(identityRequest, presentation)

    if (result.valid) {
      db.prepare('UPDATE identity_requests SET status = ?, used_at = ? WHERE id = ?').run('used', new Date().toISOString(), body.requestId)
    }

    return ctx.response.send(result)
  }
}
