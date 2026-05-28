import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT } from 'jose'
import env from '#start/env'
import { signAccessToken, verifyAccessToken } from '../../app/support/http.js'

const jwtSecret = new TextEncoder().encode(env.get('JWT_SECRET'))

describe('HTTP auth tokens', () => {
  it('signs access tokens with issuer and audience claims', async () => {
    const token = await signAccessToken('session-123')
    const payload = await verifyAccessToken(token)

    assert.equal(payload?.sub, 'session-123')
    assert.equal(payload?.iss, env.get('JWT_ISSUER'))
    assert.equal(payload?.aud, env.get('JWT_AUDIENCE'))
    assert.equal(payload?.type, 'access')
  })

  it('rejects expired access tokens', async () => {
    const token = await new SignJWT({ type: 'access' })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject('session-123')
      .setIssuer(env.get('JWT_ISSUER'))
      .setAudience(env.get('JWT_AUDIENCE'))
      .setIssuedAt(Math.floor(Date.now() / 1000) - 120)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(jwtSecret)

    assert.equal(await verifyAccessToken(token), null)
  })

  it('rejects tokens for another audience', async () => {
    const token = await new SignJWT({ type: 'access' })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject('session-123')
      .setIssuer(env.get('JWT_ISSUER'))
      .setAudience('other-api')
      .setIssuedAt()
      .setExpirationTime('1 hour')
      .sign(jwtSecret)

    assert.equal(await verifyAccessToken(token), null)
  })
})
