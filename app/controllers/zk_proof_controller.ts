import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { verifyAgeProof, verifyNullifierProof } from '../../src/services/zkpService.js'
import { getZkpArtifactDigestHeader, readVerifiedZkpArtifact } from '../../src/services/zkpArtifacts.js'
import { isAcceptableEnrollmentRoot, currentEnrollmentTree } from '../../src/services/enrollmentTree.js'
import { getSessionId, validateBody } from '#support/http'
import { z } from 'zod'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const PROVER_HTML = join(__dirname, '..', '..', '..', 'zkp', 'prover', 'prover.html')

/** The lowest age threshold a community may gate on; INE enrollment itself proves 18+. */
const MIN_NULLIFIER_AGE_THRESHOLD = 18

const nullifierProofSchema = z.object({
  proof: z.record(z.unknown()),
  publicSignals: z.array(z.string().regex(/^\d{1,80}$/)).length(5),
  communityId: z.string().regex(/^\d{1,40}$/),
}).strict()

export default class ZkProofController {
  async zkpVerify(ctx: HttpContext) {
    getSessionId(ctx)

    const body = ctx.request.body() as { proof: unknown; publicSignals: string[] }

    const valid = await verifyAgeProof(body.proof, body.publicSignals)
    if (!valid) {
      return ctx.response.status(400).send({ valid: false, reason: 'invalid_proof' })
    }

    const commitment = body.publicSignals[0] as string
    const db = getDb()
    const artifact = db.prepare(
      'SELECT status FROM proof_artifacts WHERE commitment = ? ORDER BY issued_at DESC LIMIT 1'
    ).get(commitment) as { status: string } | undefined

    if (!artifact) {
      return ctx.response.status(400).send({ valid: false, reason: 'unknown_commitment' })
    }

    if (artifact.status === 'revoked' || artifact.status === 'suspended') {
      const reason = artifact.status === 'revoked' ? 'credential_revoked' : 'credential_suspended'
      return ctx.response.status(400).send({ valid: false, reason })
    }

    return ctx.response.send({ valid: true, commitment })
  }

  /**
   * Nullifier proof v2 (CD-16): the proof shows that some active enrollment
   * in the issuer's tree joins this community, once, without saying which.
   * Only the nullifier and community are stored; not the session, and there
   * is no commitment to store.
   */
  async zkpNullifier(ctx: HttpContext) {
    getSessionId(ctx)
    const body = validateBody(ctx, nullifierProofSchema)
    if (!body) return

    const valid = await verifyNullifierProof(body.proof, body.publicSignals)
    if (!valid) {
      return ctx.response.status(400).send({ valid: false, reason: 'invalid_proof' })
    }

    // publicSignals: [root, nullifier, communityId, currentYear, ageThreshold]
    const [root, nullifier, circuitCommunityId, currentYear, ageThreshold] = body.publicSignals
    if (circuitCommunityId !== body.communityId) {
      return ctx.response.status(400).send({ valid: false, reason: 'community_mismatch' })
    }
    if (currentYear !== String(new Date().getUTCFullYear())) {
      return ctx.response.status(400).send({ valid: false, reason: 'current_year_mismatch' })
    }
    if (!(Number(ageThreshold) >= MIN_NULLIFIER_AGE_THRESHOLD && Number(ageThreshold) <= 120)) {
      return ctx.response.status(400).send({ valid: false, reason: 'age_threshold_out_of_range' })
    }
    if (!(await isAcceptableEnrollmentRoot(root))) {
      return ctx.response.status(400).send({ valid: false, reason: 'unknown_or_stale_root' })
    }

    const db = getDb()
    const { randomUUID } = await import('node:crypto')
    try {
      db.prepare('INSERT INTO nullifiers (id, nullifier, community_id, created_at) VALUES (?, ?, ?, ?)')
        .run(`nullifier-${randomUUID()}`, nullifier, body.communityId, new Date().toISOString())
    } catch (error) {
      if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
        return ctx.response.status(400).send({ valid: false, reason: 'nullifier_already_used' })
      }
      throw error
    }

    return ctx.response.send({ valid: true, nullifier })
  }

  /**
   * The issuer's enrollment tree, public so that fetching it identifies
   * nobody. Clients find their own leaf and path locally.
   */
  async enrollmentTree({ response }: HttpContext) {
    const tree = await currentEnrollmentTree()
    return response.header('cache-control', 'no-store').send(tree)
  }

  zkpProverHtml({ response }: HttpContext) {
    const html = readFileSync(PROVER_HTML, 'utf8')
    return response.header('content-type', 'text/html').send(html)
  }

  zkpProverWasm({ response }: HttpContext) {
    const wasm = readVerifiedZkpArtifact('ine_age_proof_wasm')
    return response
      .header('content-type', 'application/wasm')
      .header('digest', getZkpArtifactDigestHeader('ine_age_proof_wasm'))
      .send(wasm)
  }

  zkpProverZkey({ response }: HttpContext) {
    const zkey = readVerifiedZkpArtifact('ine_age_proof_zkey')
    return response
      .header('content-type', 'application/octet-stream')
      .header('digest', getZkpArtifactDigestHeader('ine_age_proof_zkey'))
      .send(zkey)
  }

  nullifierProverWasm({ response }: HttpContext) {
    const wasm = readVerifiedZkpArtifact('nullifier_proof_v2_wasm')
    return response
      .header('content-type', 'application/wasm')
      .header('digest', getZkpArtifactDigestHeader('nullifier_proof_v2_wasm'))
      .send(wasm)
  }

  nullifierProverZkey({ response }: HttpContext) {
    const zkey = readVerifiedZkpArtifact('nullifier_proof_v2_zkey')
    return response
      .header('content-type', 'application/octet-stream')
      .header('digest', getZkpArtifactDigestHeader('nullifier_proof_v2_zkey'))
      .send(zkey)
  }
}
