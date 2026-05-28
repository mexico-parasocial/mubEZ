import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getDb } from '../../src/db/connection.js'
import { simulateIneExtraction, simulateIneVerification } from '../../src/services/ineSimulation.js'
import { verifyAgeProof, isValidCommitment, PROOF_SCHEMA_VERSION, CIRCUIT_ID } from '../../src/services/zkpService.js'
import { hydrateSession } from '../../src/services/sessionService.js'
import { createAnonymousProfile } from '../../src/services/anonymousProfileService.js'
import { createIssuerSignedCredential } from '../../src/services/identityWallet.js'
import { Features, assertDemoPathAllowed } from '../../src/services/features.js'
import { getSessionId, validateBody, t } from '#support/http'

const ageProofSchema = z.object({
  proof: z.unknown(),
  publicSignals: z.array(z.string()).min(3),
}).strict()

const ineCredentialSchema = z.object({
  extracted: z.record(z.unknown()),
  verification: z.record(z.unknown()),
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
    const db = getDb()
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

    const existingCommitment = db.prepare(`
      SELECT id FROM proof_artifacts
      WHERE commitment = ? AND status NOT IN ('revoked', 'expired')
      LIMIT 1
    `).get(over18.commitment) as { id: string } | undefined
    if (existingCommitment) {
      return ctx.response.status(409).send({ error: 'Commitment already registered', code: 'COMMITMENT_ALREADY_REGISTERED' })
    }

    const claims = {
      age_over_18: true,
      age_over_21: over21Verified,
      citizenship: 'MX',
      district_hash: `sha256:${createHash('sha256').update(extracted.address.state + extracted.address.postalCode).digest('hex').slice(0, 16)}`,
      curp_hash: `sha256:${createHash('sha256').update(extracted.curp).digest('hex').slice(0, 16)}`,
    }
    const commitment = over18.commitment
    const revocationHash = randomBytes(32).toString('base64url')
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()

    const grantId = `grant-ine-${randomUUID()}`
    const proofArtifactId = `proof-ine-${randomUUID()}`
    const issuedAt = new Date().toISOString()

    try {
      db.transaction(() => {
        db.prepare(`
          INSERT INTO grants
          (id, session_id, app_id, app_name, app_kind, surface, requested_claims_json, proof_mode, status, reason, requested_at, issued_at, expires_at, review_note)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          grantId, sessionId, 'para.identity', 'PARA Identity', 'Verifier', 'civic',
          JSON.stringify([{ type: 'has_para_verification', disclosure: 'proof-only' }]),
          'proof-only', 'approved', $t('ine.grantReason'), issuedAt,
          issuedAt, expiresAt,
          $t('ine.reviewNote'),
        )

        db.prepare(`
          INSERT INTO proof_artifacts
          (id, session_id, grant_id, request_id, claim_type, outcome, statement, audience_app_id, audience_app_name, surface, status, issued_at, expires_at, revocation_hash, commitment, proof_schema_version, circuit_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          proofArtifactId, sessionId, grantId, 'ine-verification', 'has_para_verification', 'verified',
          `${$t('ine.statement')}: ${extracted.fullName} (${extracted.curp.slice(0, 4)}****)`,
          'para.identity', 'PARA Identity', 'civic', 'active', issuedAt,
          expiresAt,
          revocationHash, commitment, PROOF_SCHEMA_VERSION, CIRCUIT_ID,
        )
      })()
    } catch (error) {
      if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
        return ctx.response.status(409).send({ error: 'Commitment already registered', code: 'COMMITMENT_ALREADY_REGISTERED' })
      }
      throw error
    }

    const session = hydrateSession(sessionId)
    const credential = createIssuerSignedCredential({
      subjectDid: session.did,
      claims,
      revocationHash,
      expiresAt,
    })

    db.prepare(`
      INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      sessionId, $t('ledger.action.verified'), 'identity', proofArtifactId,
      JSON.stringify({
        reason: $t('ledger.reason.ineCompleted'),
        verificationId: verification.verificationId,
        curpHash: claims.curp_hash,
        commitment,
        revocationHash,
        credentialId: credential.id,
        issuerDid: credential.issuerDid,
        issuerKeyId: credential.issuerKeyId,
      }),
      new Date().toISOString(),
    )

    const anonymousProfile = createAnonymousProfile(sessionId, $t('anonymous.prefix'))

    return ctx.response.send({
      credential,
      proofArtifactId,
      verificationId: verification.verificationId,
      commitment,
      anonymousProfile,
    })
  }
}
