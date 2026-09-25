import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import env from '#start/env'
import { getDb } from '../db/connection.js'
import { getSessionIdentity, resolvePersonRoot, computeVoteNullifier } from './civicVoteIdentityService.js'

export interface DelegationClaim {
  mode: 'active' | 'passive'
  delegateTo: string
  cabildeo?: string
  party?: string
  community?: string
  scopeFlairs?: string[]
}

function canonicalClaim(input: DelegationClaim): DelegationClaim {
  const delegateTo = input.delegateTo.trim()
  if (!delegateTo.startsWith('did:') || delegateTo.length > 512) {
    throw new Error('Invalid delegation target')
  }
  if (input.mode === 'active') {
    if (!input.cabildeo?.startsWith('at://') || input.cabildeo.length > 1024) {
      throw new Error('Invalid cabildeo scope')
    }
    return { mode: 'active', delegateTo, cabildeo: input.cabildeo }
  }
  const party = input.party?.trim() ?? ''
  const community = input.community?.trim() ?? ''
  const scopeFlairs = [...new Set(input.scopeFlairs?.map((f) => f.trim()).filter(Boolean) ?? [])].sort()
  if (!party || !community || scopeFlairs.length === 0 || scopeFlairs.length > 10) {
    throw new Error('Invalid passive delegation scope')
  }
  return { mode: 'passive', delegateTo, party, community, scopeFlairs }
}

function delegationMac(id: string, actorDid: string, claim: DelegationClaim): string {
  const secret = env.get('CIVIC_VOTE_PROOF_SECRET')
  if (!secret) throw new Error('Delegation verifier unavailable')
  return createHmac('sha256', secret)
    .update(JSON.stringify(['m8:civic-delegation:v1', id, actorDid, canonicalClaim(claim)]))
    .digest('base64url')
}

export function issueCivicDelegationProof(sessionId: string, input: DelegationClaim) {
  const claim = canonicalClaim(input)
  const person = resolvePersonRoot(sessionId)
  if (person.status !== 'active') throw new Error('Person identity is not active')
  const actorDid = getSessionIdentity(sessionId).did
  const id = randomUUID()
  const eligibilityProofRef = `m8:delegation:v1:${id}:${delegationMac(id, actorDid, claim)}`
  getDb().prepare('INSERT INTO civic_delegation_grants (id, person_id) VALUES (?, ?)')
    .run(id, person.id)
  return { eligibilityProofRef }
}

/** Verify a public grant; a subject-scoped nullifier is returned only for AppView tallying. */
export function verifyCivicDelegationProof(input: DelegationClaim & {
  actorDid: string
  eligibilityProofRef: string
  subjectUri?: string
}): { voteNullifier?: string } | null {
  const match = /^m8:delegation:v1:([0-9a-f-]{36}):([A-Za-z0-9_-]{43})$/.exec(input.eligibilityProofRef)
  if (!match || !input.actorDid.startsWith('did:')) return null
  let expected: string
  try {
    expected = delegationMac(match[1], input.actorDid, input)
  } catch {
    return null
  }
  const supplied = Buffer.from(match[2])
  const expectedBytes = Buffer.from(expected)
  if (supplied.length !== expectedBytes.length || !timingSafeEqual(supplied, expectedBytes)) {
    return null
  }
  const row = getDb().prepare(`
    SELECT g.person_id FROM civic_delegation_grants g
    JOIN person_roots p ON p.id = g.person_id
    WHERE g.id = ? AND p.status = 'active'
  `).get(match[1]) as { person_id: string } | undefined
  if (!row) return null
  if (!input.subjectUri) return {}
  if (!input.subjectUri.startsWith('at://') || input.subjectUri.length > 1024) return null
  if (input.mode === 'active' && input.cabildeo !== input.subjectUri) return null
  return { voteNullifier: computeVoteNullifier(row.person_id, 'cabildeo', input.subjectUri) }
}
