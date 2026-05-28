import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'

const issuerDid = 'did:m8:ine:test-issuer'
const issuerKeyId = 'ine-ed25519-test-key'
const issuerKeys = generateKeyPairSync('ed25519')
const issuerPrivateJwk = issuerKeys.privateKey.export({ format: 'jwk' })
const issuerPublicJwk = issuerKeys.publicKey.export({ format: 'jwk' })

function productionEnv(overrides: NodeJS.ProcessEnv = {}) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: 'production',
    JWT_SECRET: 'production-jwt-secret-for-issuer-tests',
    APP_KEY: 'production-app-key',
    COOKIE_SECRET: 'production-cookie-secret',
    IDENTITY_ISSUER_DID: issuerDid,
    IDENTITY_ISSUER_PRIVATE_JWK: JSON.stringify(issuerPrivateJwk),
    IDENTITY_ISSUER_PUBLIC_JWK: JSON.stringify(issuerPublicJwk),
    IDENTITY_ISSUER_KEY_ID: issuerKeyId,
    ...overrides,
  }
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete env[key]
  }
  return env
}

describe('identity wallet issuer keys', () => {
  before(() => {
    process.env.IDENTITY_ISSUER_DID = issuerDid
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(issuerPrivateJwk)
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(issuerPublicJwk)
    process.env.IDENTITY_ISSUER_KEY_ID = issuerKeyId
  })

  it('signs and verifies credentials with configured issuer key metadata', async () => {
    const {
      createIdentityRequest,
      createDemoWalletPresentation,
      getTrustedIssuers,
      verifyWalletPresentation,
    } = await import('../../src/services/identityWallet.js')

    const request = createIdentityRequest('issuer-session', {
      audienceAppId: 'issuer-test',
      audienceAppName: 'Issuer Test',
      purpose: 'Verify configured issuer keys.',
      requestedElements: [
        { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
      ],
    })
    const presentation = createDemoWalletPresentation({
      request,
      subjectDid: 'did:plc:issuer-subject',
      selectedElementIds: ['age_over_18'],
    })

    assert.equal(presentation.credential.issuerDid, issuerDid)
    assert.equal(presentation.credential.issuerKeyId, issuerKeyId)

    const issuers = getTrustedIssuers()
    assert.equal(issuers[0].did, issuerDid)
    assert.equal(issuers[0].keyId, issuerKeyId)

    const result = verifyWalletPresentation(request, presentation, issuers)
    assert.equal(result.valid, true)
  })

  it('rejects credentials signed under an unknown issuer key id', async () => {
    const {
      createIdentityRequest,
      createDemoWalletPresentation,
      getTrustedIssuers,
      verifyWalletPresentation,
    } = await import('../../src/services/identityWallet.js')

    const request = createIdentityRequest('unknown-key-session', {
      audienceAppId: 'unknown-key-test',
      audienceAppName: 'Unknown Key Test',
      purpose: 'Reject credentials with unknown key ids.',
      requestedElements: [
        { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
      ],
    })
    const presentation = createDemoWalletPresentation({
      request,
      subjectDid: 'did:plc:unknown-key-subject',
      selectedElementIds: ['age_over_18'],
    })

    const tamperedPresentation = {
      ...presentation,
      credential: {
        ...presentation.credential,
        issuerKeyId: 'unknown-ed25519-key',
      },
    }
    const result = verifyWalletPresentation(request, tamperedPresentation, getTrustedIssuers())

    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('credential issuer is not trusted'))
  })

  it('rejects credentials when trusted issuer public key material does not match', async () => {
    const {
      createIdentityRequest,
      createDemoWalletPresentation,
      getTrustedIssuers,
      verifyWalletPresentation,
    } = await import('../../src/services/identityWallet.js')

    const request = createIdentityRequest('mismatched-key-session', {
      audienceAppId: 'mismatched-key-test',
      audienceAppName: 'Mismatched Key Test',
      purpose: 'Reject credentials with mismatched public keys.',
      requestedElements: [
        { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
      ],
    })
    const presentation = createDemoWalletPresentation({
      request,
      subjectDid: 'did:plc:mismatched-key-subject',
      selectedElementIds: ['age_over_18'],
    })
    const wrongPublicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const issuers = getTrustedIssuers().map((issuer, index) =>
      index === 0 ? { ...issuer, publicKeyPem: wrongPublicKey } : issuer
    )
    const result = verifyWalletPresentation(request, presentation, issuers)

    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('credential issuer signature is invalid'))
  })

  it('fails production issuer configuration when keys are missing', () => {
    const env = productionEnv({
      IDENTITY_ISSUER_DID: undefined,
      IDENTITY_ISSUER_PRIVATE_JWK: undefined,
      IDENTITY_ISSUER_PUBLIC_JWK: undefined,
      IDENTITY_ISSUER_KEY_ID: undefined,
    })
    const code = `
      try {
        const mod = await import('./src/services/identityWallet.ts')
        mod.assertIssuerKeyConfiguration()
        process.exit(2)
      } catch (error) {
        if (!String(error?.message ?? error).includes('IDENTITY_ISSUER')) process.exit(3)
      }
    `

    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
        cwd: process.cwd(),
        env,
        stdio: 'pipe',
      })
    })
  })

  it('resolves the same configured issuer public key across fresh processes', () => {
    const code = `
      const { getTrustedIssuers } = await import('./src/services/identityWallet.ts')
      const issuer = getTrustedIssuers()[0]
      process.stdout.write(JSON.stringify({ did: issuer.did, keyId: issuer.keyId, publicKeyPem: issuer.publicKeyPem }))
    `
    const first = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
      cwd: process.cwd(),
      env: productionEnv(),
      encoding: 'utf8',
    })
    const second = execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
      cwd: process.cwd(),
      env: productionEnv(),
      encoding: 'utf8',
    })

    assert.deepEqual(JSON.parse(first), JSON.parse(second))
  })

  it('verifies credentials signed with the previous key during rotation grace period', async () => {
    const oldKeys = generateKeyPairSync('ed25519')
    const newKeys = generateKeyPairSync('ed25519')

    // Phase 1: sign with old key
    process.env.IDENTITY_ISSUER_DID = issuerDid
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(oldKeys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(oldKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = issuerKeyId
    delete process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK
    delete process.env.IDENTITY_ISSUER_PREVIOUS_KEY_ID
    delete process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT

    const {
      resetSharedIssuerKeyStore,
      createIdentityRequest,
      createDemoWalletPresentation,
      verifyWalletPresentation,
    } = await import('../../src/services/identityWallet.js')
    resetSharedIssuerKeyStore()

    const request = createIdentityRequest('rotation-session', {
      audienceAppId: 'rotation-test',
      audienceAppName: 'Rotation Test',
      purpose: 'Verify previous key trust during rotation.',
      requestedElements: [
        { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
      ],
    })
    const presentation = createDemoWalletPresentation({
      request,
      subjectDid: 'did:plc:rotation-subject',
      selectedElementIds: ['age_over_18'],
    })

    // Phase 2: rotate to new key, keep old as previous
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(newKeys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(newKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = 'ine-ed25519-new-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK = JSON.stringify(oldKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_ID = issuerKeyId
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

    resetSharedIssuerKeyStore()

    const { getTrustedIssuers } = await import('../../src/services/identityWallet.js')
    const issuers = getTrustedIssuers()
    assert.ok(issuers.some((i) => i.keyId === 'ine-ed25519-new-key'))
    assert.ok(issuers.some((i) => i.keyId === issuerKeyId))

    const result = verifyWalletPresentation(request, presentation, issuers)
    assert.equal(result.valid, true)
  })

  it('rejects credentials signed with an unknown key even when previous key is configured', async () => {
    const oldKeys = generateKeyPairSync('ed25519')
    const newKeys = generateKeyPairSync('ed25519')
    process.env.IDENTITY_ISSUER_DID = issuerDid
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(newKeys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(newKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = 'ine-ed25519-new-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK = JSON.stringify(oldKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_ID = 'ine-ed25519-old-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()

    const {
      resetSharedIssuerKeyStore,
      createIdentityRequest,
      createDemoWalletPresentation,
      verifyWalletPresentation,
      getTrustedIssuers,
    } = await import('../../src/services/identityWallet.js')
    resetSharedIssuerKeyStore()

    const request = createIdentityRequest('unknown-key-rotation-session', {
      audienceAppId: 'unknown-key-test',
      audienceAppName: 'Unknown Key Test',
      purpose: 'Reject credentials with attacker key.',
      requestedElements: [
        { id: 'age_over_18', intentToStore: { mode: 'will-not-store' }, required: true },
      ],
    })
    const presentation = createDemoWalletPresentation({
      request,
      subjectDid: 'did:plc:attacker-subject',
      selectedElementIds: ['age_over_18'],
    })

    // Tamper to attacker key id
    const tampered = {
      ...presentation,
      credential: {
        ...presentation.credential,
        issuerKeyId: 'attacker-ed25519-key',
      },
    }

    const result = verifyWalletPresentation(request, tampered, getTrustedIssuers())
    assert.equal(result.valid, false)
    assert.ok(result.errors.includes('credential issuer is not trusted'))
  })

  it('excludes expired previous keys from trusted issuers', async () => {
    const oldKeys = generateKeyPairSync('ed25519')
    const newKeys = generateKeyPairSync('ed25519')

    process.env.IDENTITY_ISSUER_DID = issuerDid
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(newKeys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(newKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = 'ine-ed25519-new-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK = JSON.stringify(oldKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_ID = 'ine-ed25519-old-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT = new Date(Date.now() - 1000).toISOString()

    const { resetSharedIssuerKeyStore, getTrustedIssuers } = await import('../../src/services/identityWallet.js')
    resetSharedIssuerKeyStore()

    const issuers = getTrustedIssuers()
    assert.ok(issuers.some((i) => i.keyId === 'ine-ed25519-new-key'))
    assert.ok(!issuers.some((i) => i.keyId === 'ine-ed25519-old-key'))
  })

  it('excludes revoked previous keys even during the rotation grace period', async () => {
    const oldKeys = generateKeyPairSync('ed25519')
    const newKeys = generateKeyPairSync('ed25519')

    process.env.IDENTITY_ISSUER_DID = issuerDid
    process.env.IDENTITY_ISSUER_PRIVATE_JWK = JSON.stringify(newKeys.privateKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PUBLIC_JWK = JSON.stringify(newKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_KEY_ID = 'ine-ed25519-new-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK = JSON.stringify(oldKeys.publicKey.export({ format: 'jwk' }))
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_ID = 'ine-ed25519-old-key'
    process.env.IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    process.env.IDENTITY_ISSUER_REVOKED_KEY_IDS = 'ine-ed25519-old-key'

    const { resetSharedIssuerKeyStore, getIssuerMetadata, getTrustedIssuers } = await import('../../src/services/identityWallet.js')
    resetSharedIssuerKeyStore()

    const trusted = getTrustedIssuers()
    assert.ok(trusted.some((i) => i.keyId === 'ine-ed25519-new-key'))
    assert.ok(!trusted.some((i) => i.keyId === 'ine-ed25519-old-key'))

    const metadata = getIssuerMetadata()
    assert.equal(metadata.find((i) => i.keyId === 'ine-ed25519-old-key')?.status, 'revoked')

    delete process.env.IDENTITY_ISSUER_REVOKED_KEY_IDS
  })

  it('fails when the current signing key is revoked', () => {
    const env = productionEnv({
      IDENTITY_ISSUER_REVOKED_KEY_IDS: issuerKeyId,
    })
    const code = `
      try {
        const mod = await import('./src/services/identityWallet.ts')
        mod.assertIssuerKeyConfiguration()
        process.exit(2)
      } catch (error) {
        if (!String(error?.message ?? error).includes('Current issuer key is revoked')) process.exit(3)
      }
    `

    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
        cwd: process.cwd(),
        env,
        stdio: 'pipe',
      })
    })
  })
})
