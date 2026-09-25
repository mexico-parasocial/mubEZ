import { randomBytes, randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import type { createT } from '../i18n/index.js'
import type { IneExtractedData, IneVerificationResult } from '../types/index.js'
import { createAnonymousProfile } from './anonymousProfileService.js'
import { computeCurpHash, computeDistrictHash, computePersonKey } from './curpHash.js'
import { createIssuerSignedCredential } from './identityWallet.js'
import { hydrateSession } from './sessionService.js'
import { CIRCUIT_ID, PROOF_SCHEMA_VERSION } from './zkpService.js'

/**
 * Records a verified INE enrollment for a session, once its age proofs have
 * been checked: the grant, the proof artifact carrying the person key (the
 * anchor of one person, one vote), the issuer-signed credential, the ledger
 * entry and the anonymous profile. Shared by the real credential endpoint and
 * the development-only enrollment.
 */
export async function recordIneCredential(opts: {
  sessionId: string
  extracted: IneExtractedData
  verification: IneVerificationResult
  commitment: string
  over21Verified: boolean
  $t: ReturnType<typeof createT>
}) {
  const { sessionId, extracted, verification, commitment, over21Verified, $t } = opts
  const db = getDb()
  const existingCommitment = db.prepare(`
    SELECT id FROM proof_artifacts
    WHERE commitment = ? AND status NOT IN ('revoked', 'expired')
    LIMIT 1
  `).get(commitment) as { id: string } | undefined
  if (existingCommitment) {
    return { ok: false as const, status: 409 as const, error: 'Commitment already registered', code: 'COMMITMENT_ALREADY_REGISTERED' }
  }

  const claims = {
    age_over_18: true,
    age_over_21: over21Verified,
    citizenship: 'MX',
    district_hash: await computeDistrictHash(extracted.address.state, extracted.address.postalCode),
    curp_hash: await computeCurpHash(extracted.curp),
  }
  /*
   * The anchor one person one vote rests on. Derived from the deterministic
   * curp_hash, so re-enrolling — new session, new device, new commitment
   * salt — resolves to the person root already on file instead of minting a
   * second person who can vote again. Migration 035, mubEZ CD-12.
   */
  const personKey = await computePersonKey(claims.curp_hash)
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
        (id, session_id, grant_id, request_id, claim_type, outcome, statement, audience_app_id, audience_app_name, surface, status, issued_at, expires_at, revocation_hash, commitment, proof_schema_version, circuit_id, person_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        proofArtifactId, sessionId, grantId, 'ine-verification', 'has_para_verification', 'verified',
        // No PII in stored statements: only the peppered curp_hash from
        // the credential claims may be used to match an identity.
        `${$t('ine.statement')} (${claims.curp_hash})`,
        'para.identity', 'PARA Identity', 'civic', 'active', issuedAt,
        expiresAt,
        revocationHash, commitment, PROOF_SCHEMA_VERSION, CIRCUIT_ID, personKey,
      )
    })()
  } catch (error) {
    if (error instanceof Error && error.message.includes('UNIQUE constraint failed')) {
      return { ok: false as const, status: 409 as const, error: 'Commitment already registered', code: 'COMMITMENT_ALREADY_REGISTERED' }
    }
    throw error
  }

  const session = hydrateSession(sessionId)
  const credential = await createIssuerSignedCredential({
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

  return {
    ok: true as const,
    body: {
      credential,
      proofArtifactId,
      verificationId: verification.verificationId,
      commitment,
      anonymousProfile,
    },
  }
}
