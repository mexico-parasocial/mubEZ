import { defineConfig } from '@adonisjs/core/app'

export default defineConfig({
  experimental: {},
  commands: [() => import('@adonisjs/core/commands')],
  providers: [
    () => import('@adonisjs/core/providers/app_provider'),
    () => import('@adonisjs/cors/cors_provider'),
  ],
  preloads: [
    () => import('#start/m8'),
    () => import('#start/routes'),
    () => import('#start/kernel'),
  ],
  tests: {
    suites: [
      {
        files: ['tests/unit/**/*.test.{ts,js}'],
        name: 'unit',
        timeout: 2000,
      },
      {
        files: ['tests/integration/**/*.test.{ts,js}'],
        name: 'integration',
        timeout: 30000,
      },
    ],
    forceExit: false,
  },
  metaFiles: [
    'src/db/schema.sql',
    'src/db/migrations/**/*.sql',
    'src/i18n/locales/**/*.json',
    'src/openapi/openapi.json',
    'zkp/artifact-manifest.json',
    'zkp/prover/prover.html',
    'zkp/out/**/*.json',
    'zkp/out/**/*.wasm',
    'zkp/out/**/*.zkey',
  ],
})
