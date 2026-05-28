import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'

function productionEnv(overrides: NodeJS.ProcessEnv = {}) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: 'production',
    JWT_SECRET: 'production-jwt-secret-for-feature-safety',
    APP_KEY: 'production-app-key',
    COOKIE_SECRET: 'production-cookie-secret',
    IDENTITY_ISSUER_DID: 'did:m8:ine:test',
    IDENTITY_ISSUER_PRIVATE_JWK: undefined,
    IDENTITY_ISSUER_PUBLIC_JWK: undefined,
    IDENTITY_ISSUER_KEY_ID: undefined,
    ...overrides,
  }
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete env[key]
  }
  return env
}

describe('production feature safety', () => {
  it('rejects production dev-token bootstrap overrides without break-glass', () => {
    const code = `
      const { assertProductionFeatureSafety } = await import('./src/services/features.ts')
      try {
        assertProductionFeatureSafety()
        process.exit(2)
      } catch (error) {
        if (!String(error?.message ?? error).includes('m8:auth:dev_token_bootstrap')) process.exit(3)
      }
    `

    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
        cwd: process.cwd(),
        env: productionEnv({
          GROWTHBOOK_FEATURE_OVERRIDES: JSON.stringify({
            'm8:auth:dev_token_bootstrap': true,
          }),
        }),
        stdio: 'pipe',
      })
    })
  })

  it('rejects production legacy community PDS token fallback overrides without break-glass', () => {
    const code = `
      const { assertProductionFeatureSafety } = await import('./src/services/features.ts')
      try {
        assertProductionFeatureSafety()
        process.exit(2)
      } catch (error) {
        if (!String(error?.message ?? error).includes('m8:community:pds_auth_token_fallback:enable')) process.exit(3)
      }
    `

    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
        cwd: process.cwd(),
        env: productionEnv({
          GROWTHBOOK_FEATURE_OVERRIDES: JSON.stringify({
            'm8:community:pds_auth_token_fallback:enable': true,
          }),
        }),
        stdio: 'pipe',
      })
    })
  })
})
