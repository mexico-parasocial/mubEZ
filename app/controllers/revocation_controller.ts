import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { mapClaimTypeToParaRecordType } from '../../src/services/paraTrustContract.js'
import { validateRevocationTransition } from '../../src/services/paraTrustEnforcer.js'
import { getSessionId, t } from '#support/http'

export default class RevocationController {
  async revoke(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)

    const body = ctx.request.body() as { revocationHash: string; reason?: string; targetStatus?: 'revoked' | 'suspended' }
    const targetStatus = body.targetStatus ?? 'revoked'
    const db = getDb()
    const $t = t(ctx)

    const artifact = db.prepare(
      'SELECT id, session_id, status, claim_type FROM proof_artifacts WHERE revocation_hash = ?'
    ).get(body.revocationHash) as { id: string; session_id: string; status: string; claim_type: string } | undefined

    if (!artifact) {
      return ctx.response.status(404).send({ error: $t('errors.revoke.notFound') })
    }

    if (artifact.session_id !== sessionId) {
      return ctx.response.status(403).send({ error: $t('errors.revoke.wrongSession') })
    }

    const recordType = mapClaimTypeToParaRecordType(artifact.claim_type) ?? 'identity_verification'
    if (!validateRevocationTransition(artifact.status as import('../../src/services/paraTrustContract.js').ParaRevocationState, targetStatus, recordType)) {
      return ctx.response.status(400).send({ error: `Invalid revocation transition from ${artifact.status} to ${targetStatus}`, code: 'invalid_revocation_transition' })
    }

    const now = new Date().toISOString()
    db.prepare('UPDATE proof_artifacts SET status = ?, revoked_at = ? WHERE id = ?').run(targetStatus, now, artifact.id)

    db.prepare(`
      INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      sessionId, $t('ledger.action.revoked'), 'identity', artifact.id,
      JSON.stringify({ reason: body.reason ?? $t('ledger.reason.userRevoked'), revocationHash: body.revocationHash, targetStatus }),
      now,
    )

    return ctx.response.send({ revoked: targetStatus === 'revoked', suspended: targetStatus === 'suspended', status: targetStatus, revokedAt: now })
  }

  async crl(ctx: HttpContext) {
    const db = getDb()
    const since = (ctx.request.qs() as { since?: string }).since

    let rows: { revocation_hash: string; revoked_at: string }[]
    if (since) {
      rows = db.prepare(
        'SELECT revocation_hash, revoked_at FROM proof_artifacts WHERE status = ? AND revoked_at > ?'
      ).all('revoked', since) as typeof rows
    } else {
      rows = db.prepare(
        'SELECT revocation_hash, revoked_at FROM proof_artifacts WHERE status = ?'
      ).all('revoked') as typeof rows
    }

    return ctx.response.send({
      revokedHashes: rows.map((r) => r.revocation_hash),
      updatedAt: new Date().toISOString(),
    })
  }
}
