import { createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { __internal, holderBindingMessage } from '../src/services/identityWallet.js'
import type { M8IdentityCredential, M8WalletPresentation } from '../src/types/index.js'

/*
 * Regenerates docs/wallet-presentation-vectors.json (CD-14): fixed Ed25519
 * seeds for an issuer and a holder, a holder binding proof, a signed
 * credential, and a signed v2 presentation. Ed25519 is deterministic, so the
 * iM8 wallet must reproduce every signature byte for byte; copy the file to
 * iM8's src/services/__tests__/.
 *
 *   pnpm exec tsx scripts/generate-wallet-vectors.ts
 */

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function keyFromSeed(seedHex: string) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  })
  const publicKeyPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString().trim()
  return { privateKey, publicKeyPem }
}

const ISSUER_SEED = '0101010101010101010101010101010101010101010101010101010101010101'
const HOLDER_SEED = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
const issuer = keyFromSeed(ISSUER_SEED)
const holder = keyFromSeed(HOLDER_SEED)

const issuanceChallenge = 'c2hhcmVkLWlzc3VhbmNlLWNoYWxsZW5nZQ'
const bindingMessage = holderBindingMessage(issuanceChallenge)

const unsignedCredential: Omit<M8IdentityCredential, 'signature'> = {
  id: 'credential-00000000-0000-4000-8000-000000000001',
  issuerDid: 'did:m8:ine:vector-issuer',
  issuerKeyId: 'ine-ed25519-vector',
  subjectDid: 'did:plc:vectorsubjectaaaaaaaaaaa',
  issuedAt: '2026-09-01T12:00:00.000Z',
  expiresAt: '2027-09-01T12:00:00.000Z',
  claims: { age_over_18: true, citizenship: 'MX' },
  revocationHash: 'dmVjdG9yLXJldm9jYXRpb24taGFzaA',
  holderPublicKey: holder.publicKeyPem,
  signatureAlg: 'Ed25519',
}
const credentialPayload = __internal.signedCredentialPayload(unsignedCredential)
const credential: M8IdentityCredential = {
  ...unsignedCredential,
  signature: sign(null, Buffer.from(credentialPayload), issuer.privateKey).toString('base64url'),
}

const request = {
  id: 'identity-request-00000000-0000-4000-8000-000000000002',
  nonce: 'bm9uY2UtZm9yLXRoZS12ZWN0b3ItcmVxdWVzdA',
  audienceAppId: 'vector.verifier',
}
const unsignedPresentation: Omit<M8WalletPresentation, 'signature'> = {
  type: 'm8.identity.presentation.v2',
  disclosure: 'full-credential',
  requestId: request.id,
  nonce: request.nonce,
  audienceAppId: request.audienceAppId,
  credential,
  disclosedClaims: { age_over_18: true },
  issuedAt: '2026-09-02T09:00:00.000Z',
  expiresAt: '2026-09-02T09:01:30.000Z',
  signatureAlg: 'Ed25519',
}
const presentationPayload = __internal.signedPresentationPayload(unsignedPresentation)
const presentation: M8WalletPresentation = {
  ...unsignedPresentation,
  signature: sign(null, Buffer.from(presentationPayload), holder.privateKey).toString('base64url'),
}

const out = {
  description:
    'CD-14 wallet conformance vectors. Regenerate with scripts/generate-wallet-vectors.ts; never edit by hand. ' +
    'Seeds are public test values: never use them for a real key.',
  issuer: { did: unsignedCredential.issuerDid, keyId: unsignedCredential.issuerKeyId, seed: ISSUER_SEED, publicKeyPem: issuer.publicKeyPem },
  holder: { seed: HOLDER_SEED, publicKeyPem: holder.publicKeyPem },
  binding: {
    issuanceChallenge,
    message: bindingMessage,
    proof: sign(null, Buffer.from(bindingMessage), holder.privateKey).toString('base64url'),
  },
  credential: { canonicalPayload: credentialPayload, value: credential },
  request,
  presentation: {
    disclosedClaimIds: ['age_over_18'],
    canonicalPayload: presentationPayload,
    value: presentation,
  },
  verifyAt: '2026-09-02T09:00:30.000Z',
}

const here = dirname(fileURLToPath(import.meta.url))
writeFileSync(join(here, '../docs/wallet-presentation-vectors.json'), JSON.stringify(out, null, 2) + '\n')
console.log('wrote docs/wallet-presentation-vectors.json')
