import { generateKeyPairSync } from 'node:crypto'

const did = process.argv[2] ?? 'did:m8:ine:emisor-001'
const date = new Date().toISOString().slice(0, 10)
const keyId = process.argv[3] ?? `ine-ed25519-${date}`
const { privateKey, publicKey } = generateKeyPairSync('ed25519')

const privateJwk = privateKey.export({ format: 'jwk' })
const publicJwk = publicKey.export({ format: 'jwk' })

console.log(`# Generated Ed25519 issuer key material for ${did}`)
console.log('# Store IDENTITY_ISSUER_PRIVATE_JWK in a secret manager. Do not commit it.')
console.log(`IDENTITY_ISSUER_DID=${did}`)
console.log(`IDENTITY_ISSUER_KEY_ID=${keyId}`)
console.log(`IDENTITY_ISSUER_PRIVATE_JWK='${JSON.stringify(privateJwk)}'`)
console.log(`IDENTITY_ISSUER_PUBLIC_JWK='${JSON.stringify(publicJwk)}'`)
