import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { TestApp } from '../helpers/testApp.js'

const tmpDir = mkdtempSync(join(tmpdir(), 'm8-contract-test-'))
process.env.DATABASE_PATH = join(tmpDir, 'contract-test.db')

function routeToOpenApiPath(route: string) {
  return route.replace(/:([A-Za-z0-9_]+)/g, '{$1}')
}

function expectedRoutesFromSource() {
  const routes = readFileSync(new URL('../../start/routes.ts', import.meta.url), 'utf8')
  const rootRoutes = [...routes.matchAll(/router\.(get|post|patch|put|delete)\('([^']+)'/g)].map(
    (match) => routeToOpenApiPath(match[2])
  )
  const v1Routes = [...routes.matchAll(/router\.(get|post|patch|put|delete)\('([^']+)'/g)]
    .map((match) => match[2])
    .filter((route) => route !== '/docs' && route !== '/openapi.json' && route !== '/.well-known/did.json')
    .map((route) => routeToOpenApiPath(`/v1${route}`))

  return [...new Set([...rootRoutes.filter((route) => route === '/docs' || route === '/openapi.json'), ...v1Routes])]
}

describe('API contract docs', () => {
  let app: TestApp

  before(async () => {
    const { buildApp } = await import('../../src/index.js')
    app = await buildApp()
  })

  after(async () => {
    await app.close()
  })

  it('GET /openapi.json returns the OpenAPI contract', async () => {
    const res = await app.inject({ method: 'GET', url: '/openapi.json' })

    assert.equal(res.statusCode, 200)
    assert.match(res.headers['content-type'], /application\/json/)

    const spec = JSON.parse(res.payload)
    assert.equal(spec.openapi, '3.1.0')
    assert.ok(spec.paths)
    assert.ok(spec.paths['/v1/health'])
  })

  it('GET /docs returns Scalar HTML', async () => {
    const res = await app.inject({ method: 'GET', url: '/docs' })

    assert.equal(res.statusCode, 200)
    assert.match(res.headers['content-type'], /text\/html/)
    assert.match(res.payload, /@scalar\/api-reference/)
  })

  it('documents every registered route', async () => {
    const spec = JSON.parse((await app.inject({ method: 'GET', url: '/openapi.json' })).payload)
    const missing = expectedRoutesFromSource().filter((route) => !spec.paths[route])

    assert.deepEqual(missing, [])
  })
})
