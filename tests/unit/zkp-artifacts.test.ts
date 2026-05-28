import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

describe('ZKP artifact integrity', () => {
  it('verifies pinned artifacts before use', async () => {
    const {
      getZkpArtifact,
      getZkpArtifactDigestHeader,
      readVerifiedZkpArtifact,
      verifyZkpArtifactBytes,
    } = await import('../../src/services/zkpArtifacts.js')

    const artifact = getZkpArtifact('ine_age_proof_vkey')
    const bytes = readVerifiedZkpArtifact('ine_age_proof_vkey')
    const digest = Buffer.from(artifact.sha256, 'hex').toString('base64')

    assert.ok(bytes.length > 0)
    assert.equal(getZkpArtifactDigestHeader('ine_age_proof_vkey'), `sha-256=${digest}`)
    assert.throws(
      () => verifyZkpArtifactBytes('ine_age_proof_vkey', Buffer.from('tampered')),
      /ZKP artifact integrity check failed/
    )
  })
})
