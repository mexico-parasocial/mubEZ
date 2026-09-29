import { generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto'
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

/**
 * A wallet holder key and its proof of possession over the issuance
 * challenge, as /identity/ine/credential requires. On a device the private
 * key never leaves the wallet.
 */
export async function createHolderBinding(issuanceChallenge: string): Promise<{
  holderPublicKey: string
  holderKeyProof: string
  holderPrivateKey: KeyObject
}> {
  const { holderBindingMessage } = await import('../../src/services/identityWallet.js')
  const keys = generateKeyPairSync('ed25519')
  return {
    holderPublicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    holderKeyProof: sign(null, Buffer.from(holderBindingMessage(issuanceChallenge)), keys.privateKey).toString('base64url'),
    holderPrivateKey: keys.privateKey,
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

  // The credential endpoint requires the session's current issuance
  // challenge (single-use, rotated after each attempt).
  const me = await params.app.inject({
    method: 'GET',
    url: '/v1/sessions/me',
    headers: { authorization: `Bearer ${params.accessToken}` },
  })
  const { issuanceChallenge } = JSON.parse(me.payload).session
  const holder = await createHolderBinding(issuanceChallenge)

  const credentialResponse = await params.app.inject({
    method: 'POST',
    url: '/v1/identity/ine/credential',
    headers: { authorization: `Bearer ${params.accessToken}` },
    payload: {
      extracted,
      verification,
      issuanceChallenge,
      ageProofs: clientProof.ageProofs,
      holderPublicKey: holder.holderPublicKey,
      holderKeyProof: holder.holderKeyProof,
    },
  })

  return {
    extracted,
    verification,
    clientProof,
    issuanceChallenge,
    holderPrivateKey: holder.holderPrivateKey,
    response: credentialResponse,
    body: JSON.parse(credentialResponse.payload),
  }
}
