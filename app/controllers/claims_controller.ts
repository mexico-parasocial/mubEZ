import { randomUUID } from 'node:crypto'
import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { verifyClaim } from '../../src/services/trustPolicy.js'
import { PROOF_BROKER_CLAIM_TYPES } from '../../src/types/index.js'
import { getSessionId, validateBody } from '#support/http'

const verifyClaimSchema = z.object({
  claimType: z.enum(PROOF_BROKER_CLAIM_TYPES),
  requestedValue: z.string().optional(),
  audienceAppId: z.string().min(1),
  audienceAppName: z.string().min(1),
  surface: z.enum(['public', 'civic', 'dating']),
  proofMode: z.enum(['proof-only', 'signed-claim', 'raw']),
  verifierId: z.enum(['para.identity', 'm8.broker']),
  reason: z.string().min(1),
})

export default class ClaimsController {
  async verify(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, verifyClaimSchema)
    if (!body) return

    const result = verifyClaim({ sessionId, ...body })
    const proofId = `proof-${randomUUID()}`
    const now = new Date().toISOString()

    getDb()
      .prepare(
        `
      INSERT INTO proof_artifacts (id, session_id, grant_id, request_id, claim_type, requested_value, outcome, statement, proof_mode, issuer_id, verifier_id, audience_app_id, audience_app_name, surface, reference, status, issued_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
      )
      .run(
        proofId,
        sessionId,
        'direct-verify',
        ctx.params.id,
        body.claimType,
        body.requestedValue ?? null,
        result.outcome,
        result.statement,
        body.proofMode,
        body.verifierId,
        body.verifierId,
        body.audienceAppId,
        body.audienceAppName,
        body.surface,
        result.reference ?? '',
        'active',
        now
      )

    return ctx.response.send({ proofId, ...result })
  }
}
