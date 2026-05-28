import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { getSessionId } from '#support/http'

export default class LedgerController {
  async index(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const db = getDb()

    const ledgerRows = db.prepare(
      'SELECT * FROM ledger WHERE session_id = ? ORDER BY created_at DESC'
    ).all(sessionId) as Record<string, unknown>[]

    const ledger = ledgerRows.map((r) => ({
      id: r.id as number,
      action: r.action as string,
      targetType: r.target_type as string,
      targetId: r.target_id as string,
      detail: JSON.parse((r.detail_json as string) || '{}'),
      createdAt: r.created_at as string,
    }))

    const grantRows = db.prepare(
      'SELECT * FROM grants WHERE session_id = ? ORDER BY requested_at DESC'
    ).all(sessionId) as Record<string, unknown>[]

    const grants = grantRows.map((r) => ({
      id: r.id as string,
      appId: r.app_id as string,
      appName: r.app_name as string,
      appKind: r.app_kind as string,
      surface: r.surface as string,
      requestedClaims: JSON.parse(r.requested_claims_json as string),
      proofMode: r.proof_mode as string,
      status: r.status as string,
      reason: r.reason as string,
      requestedAt: r.requested_at as string,
      issuedAt: r.issued_at as string | null,
      expiresAt: r.expires_at as string | null,
      reviewNote: r.review_note as string | null,
    }))

    const proofRows = db.prepare(
      'SELECT * FROM proof_artifacts WHERE session_id = ? ORDER BY issued_at DESC'
    ).all(sessionId) as Record<string, unknown>[]

    const proofs = proofRows.map((r) => ({
      id: r.id as string,
      grantId: r.grant_id as string,
      claimType: r.claim_type as string,
      outcome: r.outcome as string,
      statement: r.statement as string,
      audienceAppId: r.audience_app_id as string,
      audienceAppName: r.audience_app_name as string,
      surface: r.surface as string,
      status: r.status as string,
      issuedAt: r.issued_at as string,
      expiresAt: r.expires_at as string | null,
      revokedAt: r.revoked_at as string | null,
    }))

    const totalRequests = grants.length
    const activeGrants = grants.filter((g) => g.status === 'approved').length
    const revokedGrants = grants.filter((g) => g.status === 'revoked').length
    const totalProofs = proofs.length
    const activeProofs = proofs.filter((p) => p.status === 'active').length

    return ctx.response.send({
      ledger,
      grants,
      proofs,
      summary: {
        totalRequests,
        activeGrants,
        revokedGrants,
        totalProofs,
        activeProofs,
      },
    })
  }
}
