import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-chat-key-backup-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'test.db')

let buildApp: typeof import('../../src/index.js').buildApp
let closeDb: typeof import('../../src/db/connection.js').closeDb

describe('chat key backup integration', () => {
  let app: TestApp
  let accessToken: string

  before(async () => {
    ;({ buildApp } = await import('../../src/index.js'))
    ;({ closeDb } = await import('../../src/db/connection.js'))
    app = await buildApp()
    const start = await app.inject({
      method: 'POST',
      url: '/v1/sessions/start',
      payload: { identifier: 'chatbackup.bsky.social' },
    })
    const body = JSON.parse(start.payload)
    accessToken = body.tokens.accessToken
  })

  after(async () => {
    await app.close()
    closeDb()
  })

  it('stores and returns only an opaque encrypted backup blob', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/chat-key-backup',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        version: 1,
        deviceId: 'device-1',
        ciphertext: 'base64-client-encrypted-backup',
        encryptionMetadata: {
          algorithm: 'xchacha20poly1305',
          kdf: 'argon2id',
        },
      },
    })

    assert.equal(res.statusCode, 200)

    const get = await app.inject({
      method: 'GET',
      url: '/v1/identity/chat-key-backup',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(get.statusCode, 200)
    const body = JSON.parse(get.payload)
    assert.equal(body.version, 1)
    assert.equal(body.deviceId, 'device-1')
    assert.equal(body.ciphertext, 'base64-client-encrypted-backup')
    assert.equal(body.encryptionMetadata.algorithm, 'xchacha20poly1305')
    assert.equal(body.plaintextKey, undefined)
  })

  it('rejects extra plaintext key material fields', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/identity/chat-key-backup',
      headers: { authorization: `Bearer ${accessToken}` },
      payload: {
        version: 1,
        deviceId: 'device-1',
        ciphertext: 'base64-client-encrypted-backup',
        encryptionMetadata: {},
        plaintextKey: 'do-not-store',
      },
    })

    assert.equal(res.statusCode, 400)
  })

  it('deletes the backup for the authenticated session', async () => {
    const del = await app.inject({
      method: 'DELETE',
      url: '/v1/identity/chat-key-backup',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(del.statusCode, 200)
    assert.equal(JSON.parse(del.payload).deleted, true)

    const get = await app.inject({
      method: 'GET',
      url: '/v1/identity/chat-key-backup',
      headers: { authorization: `Bearer ${accessToken}` },
    })
    assert.equal(get.statusCode, 404)
  })
})
