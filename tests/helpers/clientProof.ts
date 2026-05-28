import { randomBytes } from 'node:crypto'
import type { TestApp } from './testApp.js'

/**
 * Generate a cryptographically random 256-bit salt as a decimal string.
 * In production this must run on the client device using a CSPRNG.
 */
export function generateCsprngSalt(): bigint {
  const buf = randomBytes(32)
  let hex = '0x'
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0')
  }
  return BigInt(hex)
}

export async function buildAgeProofs(params: {
  birthDate: string
  salt?: number | string | bigint
  over21?: boolean
}) {
  const birthYear = new Date(params.birthDate).getFullYear()
  const currentYear = new Date().getFullYear()
  const { generateAgeProof } = await import('../../src/services/zkpService.js')
  const salt = params.salt ?? generateCsprngSalt()
  const over18 = await generateAgeProof({
    birthYear,
    salt,
    currentYear,
    ageThreshold: 18,
  })
  const over21 = params.over21 === true
    ? await generateAgeProof({
        birthYear,
        salt,
        currentYear,
        ageThreshold: 21,
      })
    : undefined

  return {
    witness: { birthYear, salt },
    ageProofs: {
      over18: { proof: over18.proof, publicSignals: over18.publicSignals },
      ...(over21 ? { over21: { proof: over21.proof, publicSignals: over21.publicSignals } } : {}),
    },
    commitment: over18.commitment,
  }
}

export async function issueIneCredentialWithClientProof(params: {
  app: TestApp
  accessToken: string
  inePhotoBase64: string
  selfieBase64: string
  salt?: number | string | bigint
  over21?: boolean
}) {
  const analyze = await params.app.inject({
    method: 'POST',
    url: '/v1/identity/ine/analyze',
    headers: { authorization: `Bearer ${params.accessToken}` },
    payload: { inePhotoBase64: params.inePhotoBase64, simulatedMode: true },
  })
  const { extracted } = JSON.parse(analyze.payload)

  const verify = await params.app.inject({
    method: 'POST',
    url: '/v1/identity/ine/verify',
    headers: { authorization: `Bearer ${params.accessToken}` },
    payload: { extracted, selfieBase64: params.selfieBase64, consentToStore: true },
  })
  const verification = JSON.parse(verify.payload)
  const clientProof = await buildAgeProofs({
    birthDate: extracted.birthDate,
    salt: params.salt,
    over21: params.over21,
  })

  const credentialResponse = await params.app.inject({
    method: 'POST',
    url: '/v1/identity/ine/credential',
    headers: { authorization: `Bearer ${params.accessToken}` },
    payload: { extracted, verification, ageProofs: clientProof.ageProofs },
  })

  return {
    extracted,
    verification,
    clientProof,
    response: credentialResponse,
    body: JSON.parse(credentialResponse.payload),
  }
}
