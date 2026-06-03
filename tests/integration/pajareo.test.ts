import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SignJWT } from 'jose'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-pajareo-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'pajareo-test.db')
process.env.JWT_SECRET = 'pajareo-test-secret-minimum-32-chars'
process.env.GROWTHBOOK_FEATURE_OVERRIDES = JSON.stringify({
  'm8:pajareo:enable': true,
  'm8:development_device_trust:enable': true,
})

describe('Pajareo integration', () => {
  let app: TestApp
  let accessToken: string
  let publicAccessToken: string
  let officialAccessToken: string

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()

    accessToken = await seedSession('citizen-session', 'did:plc:pajareo-citizen')
    publicAccessToken = await seedSession('public-response-session', 'did:plc:public-responder')
    officialAccessToken = await seedSession('official-response-session', 'did:plc:alice')
  })

  after(async () => {
    await app.close()
  })

  it('creates Pajareo entries on a dedicated isolated anonymous identity', async () => {
    const initialIdentities = await authed('GET', '/v1/anonymous/identities', accessToken)
    const defaultIdentity = JSON.parse(initialIdentities.payload).identities[0]
    assert.notEqual(defaultIdentity.communityUri, 'm8:pajareo')

    const created = await authed('POST', '/v1/pajareo/representatives/fed_exec_1/entries', accessToken, {
      type: 'pregunta',
      body: '¿Cuándo publicarán el calendario de seguimiento?',
    })
    assert.equal(created.statusCode, 201)
    const entry = JSON.parse(created.payload).entry
    assert.equal(entry.representativeId, 'fed_exec_1')
    assert.equal(entry.anonymousDisplayArea, 'Persona verificada de México')

    const identities = await authed('GET', '/v1/anonymous/identities', accessToken)
    const cards = JSON.parse(identities.payload).identities
    const pajareoCard = cards.find((identity: Record<string, unknown>) => identity.communityUri === 'm8:pajareo')
    const defaultCard = cards.find((identity: Record<string, unknown>) => identity.id === defaultIdentity.id)

    assert.ok(pajareoCard)
    assert.notEqual(pajareoCard.id, defaultIdentity.id)
    assert.equal(
      pajareoCard.posts.some((post: Record<string, unknown>) => post.postType === 'pajareo.entry'),
      true,
    )
    assert.equal(
      defaultCard.posts.some((post: Record<string, unknown>) => post.postType === 'pajareo.entry'),
      false,
    )
  })

  it('does not expose citizen author internals in the public representative feed', async () => {
    const feed = await app.inject({
      method: 'GET',
      url: '/v1/pajareo/representatives/fed_exec_1',
    })
    assert.equal(feed.statusCode, 200)
    const body = JSON.parse(feed.payload)
    assert.ok(body.entries.length >= 1)

    const serialized = JSON.stringify(body)
    assert.equal(serialized.includes('identityId'), false)
    assert.equal(serialized.includes('anonymousIdentityId'), false)
    assert.equal(serialized.includes('sessionId'), false)
    assert.equal(serialized.includes('proofArtifactIds'), false)
    assert.equal(serialized.includes('nullifier'), false)
  })

  it('stores institution targets and geographic specificity on public entries', async () => {
    const created = await authed('POST', '/v1/pajareo/representatives/gov_nl_1/entries', accessToken, {
      type: 'testimonio',
      body: 'Hay fallas recurrentes en la atención regional.',
      subject: {
        kind: 'institution',
        institutionId: 'institution:salud-nuevo-leon',
        institutionName: 'Secretaría de Salud de Nuevo León',
      },
      jurisdiction: {
        level: 'state',
        label: 'Nuevo León',
      },
    })
    assert.equal(created.statusCode, 201)
    const entry = JSON.parse(created.payload).entry
    assert.equal(entry.subject.kind, 'institution')
    assert.equal(entry.subject.personId, null)
    assert.equal(entry.subject.institutionName, 'Secretaría de Salud de Nuevo León')
    assert.equal(entry.jurisdiction.level, 'state')
    assert.equal(entry.jurisdiction.label, 'Nuevo León')
    assert.equal(entry.anonymousDisplayArea, 'Persona verificada de Nuevo León')

    const feed = await app.inject({
      method: 'GET',
      url: '/v1/pajareo/representatives/gov_nl_1',
    })
    const hydrated = JSON.parse(feed.payload).entries.find((item: Record<string, unknown>) => item.id === entry.id)
    assert.equal(hydrated.subject.institutionName, 'Secretaría de Salud de Nuevo León')
    assert.equal(hydrated.jurisdiction.label, 'Nuevo León')
  })

  it('creates a new active Pajareo card when the previous isolated card is archived', async () => {
    const identities = await authed('GET', '/v1/anonymous/identities', accessToken)
    const pajareoCard = JSON.parse(identities.payload).identities.find(
      (identity: Record<string, unknown>) => identity.communityUri === 'm8:pajareo',
    )
    assert.ok(pajareoCard)

    const archived = await authed('PATCH', `/v1/anonymous/identities/${pajareoCard.id}`, accessToken, {
      status: 'archived',
    })
    assert.equal(archived.statusCode, 200)

    const created = await authed('POST', '/v1/pajareo/representatives/fed_exec_1/entries', accessToken, {
      type: 'señal',
      body: 'Seguimiento ciudadano adicional.',
    })
    assert.equal(created.statusCode, 201)

    const after = await authed('GET', '/v1/anonymous/identities', accessToken)
    const activePajareoCards = JSON.parse(after.payload).identities.filter(
      (identity: Record<string, unknown>) =>
        identity.communityUri === 'm8:pajareo' && identity.status === 'active',
    )
    assert.equal(activePajareoCards.length, 1)
    assert.notEqual(activePajareoCards[0].id, pajareoCard.id)
  })

  it('supports entries idempotently per session', async () => {
    const feed = await app.inject({
      method: 'GET',
      url: '/v1/pajareo/representatives/fed_exec_1',
    })
    const entry = JSON.parse(feed.payload).entries[0]

    const first = await authed('POST', `/v1/pajareo/entries/${entry.id}/support`, accessToken)
    assert.equal(first.statusCode, 200)
    const firstCount = JSON.parse(first.payload).entry.supportCount

    const second = await authed('POST', `/v1/pajareo/entries/${entry.id}/support`, accessToken)
    assert.equal(second.statusCode, 200)
    assert.equal(JSON.parse(second.payload).entry.supportCount, firstCount)
  })

  it('accepts public responses and marks verified controller responses official', async () => {
    const created = await authed('POST', '/v1/pajareo/representatives/gov_nl_1/entries', accessToken, {
      type: 'pregunta',
      body: '¿Habrá una mesa pública de seguimiento?',
    })
    const entry = JSON.parse(created.payload).entry

    const publicResponse = await authed('POST', `/v1/pajareo/entries/${entry.id}/responses`, publicAccessToken, {
      body: 'También me interesa la respuesta.',
    })
    assert.equal(publicResponse.statusCode, 201)
    assert.equal(JSON.parse(publicResponse.payload).response.kind, 'public')

    const officialResponse = await authed('POST', `/v1/pajareo/entries/${entry.id}/responses`, officialAccessToken, {
      body: 'Respuesta oficial: se publicará una mesa de seguimiento.',
    })
    assert.equal(officialResponse.statusCode, 201)
    assert.equal(JSON.parse(officialResponse.payload).response.kind, 'official')

    const feed = await app.inject({
      method: 'GET',
      url: '/v1/pajareo/representatives/gov_nl_1',
    })
    const hydrated = JSON.parse(feed.payload).entries.find((item: Record<string, unknown>) => item.id === entry.id)
    assert.equal(hydrated.responses.length, 2)
    assert.equal(hydrated.officialResponse.entityName, 'Gobierno de Nuevo León')
    assert.equal(hydrated.questionAnswered, true)
  })

  async function authed(method: string, url: string, token: string, payload?: unknown) {
    return app.inject({
      method,
      url,
      headers: { authorization: `Bearer ${token}` },
      payload,
    })
  }
})

async function seedSession(sessionId: string, did: string) {
  const { getDb } = await import('../../src/db/connection.js')
  const now = new Date().toISOString()
  getDb().prepare(`
    INSERT INTO sessions
      (session_id, did, handle, display_name, authorization_server, authenticated_at, pds_safety_json, active_persona_id, active_surface_id, oauth_scope, created_at, updated_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    sessionId,
    did,
    did,
    did,
    'https://pds.test',
    now,
    JSON.stringify({
      state: 'Enroll now',
      detail: 'No PDS backup configured for this identity.',
      source: 'm8.broker',
      lastBackup: now,
    }),
    'orbit',
    'public',
    'atproto',
    now,
    now,
    'active',
  )

  return signTestAccessToken(sessionId)
}

function signTestAccessToken(sessionId: string) {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({ type: 'access' })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(sessionId)
    .setIssuer(process.env.JWT_ISSUER ?? 'mubez')
    .setAudience(process.env.JWT_AUDIENCE ?? 'm8.api')
    .setIssuedAt(now)
    .setExpirationTime(now + 86400)
    .sign(new TextEncoder().encode(process.env.JWT_SECRET))
}
