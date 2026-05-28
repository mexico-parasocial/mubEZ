import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { cleanHandle } from '../../src/services/didResolver.js'
import { getLastPlcOperation } from '../../src/services/atproto/plcDirectoryService.js'

describe('ATProto resolution helpers', () => {
  it('cleans handles copied with decoration or invisible unicode marks', () => {
    assert.equal(cleanHandle('@alice.example.com'), 'alice.example.com')
    assert.equal(cleanHandle('\u202A@partido.example.com\u202C'), 'partido.example.com')
    assert.equal(cleanHandle('  \u2066@comunidad.example.com\u2069  '), 'comunidad.example.com')
  })

  it('extracts the last PLC operation without publishing changes', () => {
    const logs = [
      { cid: 'one', operation: { rotationKeys: ['did:key:first'] } },
      { cid: 'two', operation: { rotationKeys: ['did:key:second'], prev: 'one' } },
    ]

    assert.deepEqual(getLastPlcOperation(logs), {
      operation: { rotationKeys: ['did:key:second'], prev: 'one' },
      base: logs[1],
    })
  })
})
