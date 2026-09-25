import { randomBytes } from 'node:crypto'
import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import env from '#start/env'
import { getDb } from '../../src/db/connection.js'
import { simulateIneExtraction, simulateIneVerification } from '../../src/services/ineSimulation.js'
import { generateAgeProof, verifyAgeProof, isValidCommitment } from '../../src/services/zkpService.js'
import { recordIneCredential } from '../../src/services/ineCredentialService.js'
import { hydrateSession } from '../../src/services/sessionService.js'
import { isValidIssuanceChallenge, rotateIssuanceChallenge } from '../../src/services/issuanceChallenge.js'
import { Features, assertDemoPathAllowed } from '../../src/services/features.js'
import { getSessionId, validateBody, t } from '#support/http'

const ageProofSchema = z.object({
  proof: z.unknown(),
  publicSignals: z.array(z.string()).min(3),
}).strict()

const ineCredentialSchema = z.object({
  extracted: z.record(z.unknown()),
  verification: z.record(z.unknown()),
  issuanceChallenge: z.string().min(1),
  ageProofs: z.object({
    over18: ageProofSchema,
    over21: ageProofSchema.optional(),
  }).strict(),
}).strict()

type AgeProofPayload = z.infer<typeof ageProofSchema>

async function verifyAgeProofPayload(
  payload: AgeProofPayload,
  expectedAgeThreshold: number,
  expectedCurrentYear: number,
) {
  const [commitment, currentYear, ageThreshold] = payload.publicSignals
  if (currentYear !== String(expectedCurrentYear)) {
    return { valid: false as const, reason: 'current_year_mismatch' }
  }
  if (ageThreshold !== String(expectedAgeThreshold)) {
    return { valid: false as const, reason: 'age_threshold_mismatch' }
  }
  if (!(await verifyAgeProof(payload.proof, payload.publicSignals))) {
    return { valid: false as const, reason: 'invalid_proof' }
  }
  return { valid: true as const, commitment }
}

export default class IneController {
  async ineAnalyze(ctx: HttpContext) {
    getSessionId(ctx)
    if (!assertDemoPathAllowed(Features.SimulatedIneEnable)) {
      return ctx.response.status(404).send({
        error: 'Simulated INE extraction is disabled',
        code: 'FEATURE_DISABLED',
      })
    }

    const body = ctx.request.body() as { inePhotoBase64?: string; selfieBase64?: string; simulatedMode?: boolean }
    const result = simulateIneExtraction(body.inePhotoBase64 ?? '')
    return ctx.response.send(result)
  }

  async ineVerify(ctx: HttpContext) {
    getSessionId(ctx)
    if (!assertDemoPathAllowed(Features.SimulatedIneEnable)) {
      return ctx.response.status(404).send({
        error: 'Simulated INE verification is disabled',
        code: 'FEATURE_DISABLED',
      })
    }

    const body = ctx.request.body() as { extracted: import('../../src/types/index.js').IneExtractedData; selfieBase64?: string; consentToStore?: boolean }
    const result = simulateIneVerification(body.extracted, body.selfieBase64 ?? '')
    return ctx.response.send(result)
  }

  async ineCredential(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    if (!assertDemoPathAllowed(Features.SimulatedIneEnable)) {
      return ctx.response.status(404).send({
        error: 'Simulated INE credential issuance is disabled',
        code: 'FEATURE_DISABLED',
      })
    }

    const body = validateBody(ctx, ineCredentialSchema)
    if (!body) return

    // Replay protection: the issuance challenge is single-use. A wrong
    // challenge is rejected without rotation (so an attacker cannot burn the
    // legitimate one); a valid challenge is rotated immediately so this exact
    // request can never be replayed.
    if (!isValidIssuanceChallenge(sessionId, body.issuanceChallenge)) {
      return ctx.response.status(403).send({
        error: 'Invalid or expired issuance challenge',
        code: 'ISSUANCE_CHALLENGE_INVALID',
      })
    }
    rotateIssuanceChallenge(sessionId)

    const $t = t(ctx)
    const extracted = body.extracted as import('../../src/types/index.js').IneExtractedData
    const verification = body.verification as import('../../src/types/index.js').IneVerificationResult

    const now = new Date()
    const currentYear = now.getFullYear()
    const over18 = await verifyAgeProofPayload(body.ageProofs.over18, 18, currentYear)
    if (!over18.valid) {
      return ctx.response.status(400).send({ error: 'Invalid over-18 age proof', code: over18.reason })
    }
    if (!isValidCommitment(over18.commitment)) {
      return ctx.response.status(400).send({ error: 'Invalid commitment', code: 'invalid_commitment' })
    }

    let over21Verified = false
    if (body.ageProofs.over21) {
      const over21 = await verifyAgeProofPayload(body.ageProofs.over21, 21, currentYear)
      if (!over21.valid) {
        return ctx.response.status(400).send({ error: 'Invalid over-21 age proof', code: over21.reason })
      }
      if (over21.commitment !== over18.commitment) {
        return ctx.response.status(400).send({ error: 'Age proof commitments do not match', code: 'commitment_mismatch' })
      }
      over21Verified = true
    }

    const result = await recordIneCredential({
      sessionId,
      extracted,
      verification,
      commitment: over18.commitment,
      over21Verified,
      $t,
    })
    if (!result.ok) {
      return ctx.response.status(result.status).send({ error: result.error, code: result.code })
    }
    return ctx.response.send(result.body)
  }

  /**
   * Development only: enrolls the current session with a simulated INE, so a
   * local account can vote without the photo and proof flow of the wallet.
   * The simulated identity is derived from the session's DID, so each local
   * account is its own person, and re-enrolling the same account resolves to
   * the same person (and the same vote nullifiers). Age proofs are generated
   * here, which production never does. Refused unless simulated INE is
   * allowed and NODE_ENV is not production.
   */
  async devEnroll(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    if (
      env.get('NODE_ENV') === 'production' ||
      !assertDemoPathAllowed(Features.SimulatedIneEnable)
    ) {
      return ctx.response.status(404).send({
        error: 'Development INE enrollment is disabled',
        code: 'FEATURE_DISABLED',
      })
    }

    const enrolled = getDb().prepare(`
      SELECT id FROM proof_artifacts
      WHERE session_id = ? AND request_id = 'ine-verification'
        AND outcome = 'verified' AND status = 'active'
      LIMIT 1
    `).get(sessionId) as { id: string } | undefined
    if (enrolled) {
      return ctx.response.send({ enrolled: true, proofArtifactId: enrolled.id, created: false })
    }

    const { did } = hydrateSession(sessionId)
    const seed = Buffer.from(`para-dev-enroll:${did}`).toString('base64')
    const { extracted } = simulateIneExtraction(seed)
    const verification = simulateIneVerification(extracted, seed)
    const currentYear = new Date().getFullYear()
    const over18 = await generateAgeProof({
      birthYear: new Date(extracted.birthDate).getFullYear(),
      salt: BigInt('0x' + randomBytes(31).toString('hex')),
      currentYear,
      ageThreshold: 18,
    })

    const result = await recordIneCredential({
      sessionId,
      extracted,
      verification,
      commitment: over18.commitment,
      over21Verified: false,
      $t: t(ctx),
    })
    if (!result.ok) {
      return ctx.response.status(result.status).send({ error: result.error, code: result.code })
    }
    return ctx.response.send({
      enrolled: true,
      proofArtifactId: result.body.proofArtifactId,
      created: true,
    })
  }
}
