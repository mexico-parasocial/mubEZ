import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync, verify, type KeyObject } from 'node:crypto'
import {
  EnvIssuerKeyStore,
  EnvIssuerSigner,
  getSharedIssuerSigner,
  resetSharedIssuerKeyStore,
  type IssuerSigner,
} from '../../src/services/issuerKeyStore.js'

const issuerDid = 'did:m8:ine:signer-test'
const issuerKeyId = 'ine-ed25519-signer-test'
const keys = generateKeyPairSync('ed25519')

const saved: Record<string, string | undefined> = {}
const ENV_KEYS = [
  'IDENTITY_ISSUER_DID',
  'IDENTITY_ISSUER_PRIVATE_JWK',
  'IDENTITY_ISSUER_PUBLIC_JWK',
  'IDENTITY_ISSUER_KEY_ID',
]

describe('issuer signer boundary', () => {
  before(() => {
    for (const key of ENV_KEYS) saved[key] = process.env[key]
    process.env.IDENTITY_ISSUER_DID = issuerDid
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(keys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(keys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = issuerKeyId
    resetSharedIssuerKeyStore()
  })

  after(() => {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key]
      else process.env[key] = saved[key]
    }
    resetSharedIssuerKeyStore()
  })

  it('produces signatures verifiable with the advertised public key', async () => {
    const signer = getSharedIssuerSigner()
    const info = await signer.getInfo()
    assert.equal(info.did, issuerDid)
    assert.equal(info.keyId, issuerKeyId)

    const payload = Buffer.from('m8 issuer signer payload')
    const signature = await signer.sign(payload)
    assert.equal(verify(null, payload, info.publicKeyPem, Buffer.from(signature)), true)
  })

  it('rejects a tampered payload against the same signature', async () => {
    const signer = getSharedIssuerSigner()
    const info = await signer.getInfo()
    const signature = await signer.sign(Buffer.from('original payload'))
    assert.equal(
      verify(null, Buffer.from('tampered payload'), info.publicKeyPem, Buffer.from(signature)),
      false,
    )
  })

  /*
   * The reason this reshape exists: a KMS-backed signer physically cannot
   * return a private key, so no caller may depend on getting one. If a
   * private key ever becomes reachable through the IssuerSigner surface,
   * the KMS implementation cannot satisfy the same interface.
   */
  it('never exposes private key material through the signer surface', async () => {
    const signer: IssuerSigner = getSharedIssuerSigner()
    const info = await signer.getInfo()

    assert.deepEqual(Object.keys(info).sort(), ['did', 'keyId', 'publicKeyPem'])
    for (const value of Object.values(info) as unknown[]) {
      assert.equal(typeof value, 'string')
      assert.doesNotMatch(value as string, /PRIVATE KEY/)
    }

    const reachable = [...Object.values(signer), ...Object.values(info)] as unknown[]
    for (const value of reachable) {
      assert.notEqual((value as KeyObject)?.type, 'private')
    }
  })

  it('signs with whichever key the store currently holds, without caching key material', async () => {
    const first = new EnvIssuerSigner(new EnvIssuerKeyStore())
    const payload = Buffer.from('rotation payload')
    const beforeSig = await first.sign(payload)
    const beforeInfo = await first.getInfo()
    assert.equal(verify(null, payload, beforeInfo.publicKeyPem, Buffer.from(beforeSig)), true)

    const rotated = generateKeyPairSync('ed25519')
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(rotated.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(rotated.publicKey.export({ format: 'jwk' }))

    // A fresh store picks up the rotated key; the old signature stays valid
    // only under the old public key.
    const second = new EnvIssuerSigner(new EnvIssuerKeyStore())
    const afterInfo = await second.getInfo()
    const afterSig = await second.sign(payload)
    assert.notEqual(afterInfo.publicKeyPem, beforeInfo.publicKeyPem)
    assert.equal(verify(null, payload, afterInfo.publicKeyPem, Buffer.from(afterSig)), true)
    assert.equal(verify(null, payload, afterInfo.publicKeyPem, Buffer.from(beforeSig)), false)

    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(keys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(keys.publicKey.export({ format: 'jwk' }))
    resetSharedIssuerKeyStore()
  })
})
