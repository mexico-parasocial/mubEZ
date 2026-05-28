import { createECDH, createPrivateKey, randomBytes, sign, type JsonWebKey } from 'node:crypto'

const SECP256K1_PUBLIC_MULTICODEC = Buffer.from([0xe7, 0x01])
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

export type CommunityAtprotoKeypair = {
  privateJwk: JsonWebKey
  publicMultibase: string
  keyType: 'secp256k1'
  keyId: string
}

export function generateCommunityAtprotoKeypair(did: string): CommunityAtprotoKeypair {
  const privateBytes = randomBytes(32)
  const publicBytes = getSecp256k1PublicKey(privateBytes)
  const x = publicBytes.subarray(1, 33)
  const y = publicBytes.subarray(33, 65)

  const privateJwk: JsonWebKey = {
    kty: 'EC',
    crv: 'secp256k1',
    x: x.toString('base64url'),
    y: y.toString('base64url'),
    d: privateBytes.toString('base64url'),
  }

  return {
    privateJwk,
    publicMultibase: secp256k1PublicKeyToMultibase(publicBytes),
    keyType: 'secp256k1',
    keyId: `${did}#atproto`,
  }
}

export function signEs256kCompactJwt(input: string, privateJwk: JsonWebKey): string {
  const privateKey = createPrivateKey({ key: privateJwk, format: 'jwk' })
  return sign('sha256', Buffer.from(input), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url')
}

export function secp256k1PublicKeyToMultibase(uncompressedPublicKey: Buffer): string {
  if (uncompressedPublicKey.length !== 65 || uncompressedPublicKey[0] !== 0x04) {
    throw new Error('Expected uncompressed secp256k1 public key')
  }

  const x = uncompressedPublicKey.subarray(1, 33)
  const y = uncompressedPublicKey.subarray(33, 65)
  const compressedPrefix = (y[y.length - 1] & 1) === 1 ? 0x03 : 0x02
  const compressed = Buffer.concat([Buffer.from([compressedPrefix]), x])
  return `z${base58Encode(Buffer.concat([SECP256K1_PUBLIC_MULTICODEC, compressed]))}`
}

function getSecp256k1PublicKey(privateBytes: Buffer): Buffer {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(privateBytes)
  return ecdh.getPublicKey(undefined, 'uncompressed')
}

function base58Encode(bytes: Buffer): string {
  let value = BigInt(`0x${bytes.toString('hex')}`)
  let encoded = ''

  while (value > 0n) {
    const remainder = Number(value % 58n)
    encoded = BASE58_ALPHABET[remainder] + encoded
    value /= 58n
  }

  for (const byte of bytes) {
    if (byte === 0) encoded = BASE58_ALPHABET[0] + encoded
    else break
  }

  return encoded || BASE58_ALPHABET[0]
}
