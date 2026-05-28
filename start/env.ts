import { Env } from '@adonisjs/core/env'
import { z } from 'zod'
import type { ValidateFn } from '@poppinss/validator-lite/types'

/**
 * Convert a Zod schema into an Adonis Env validation function.
 * Preserves all rich validation (min length, defaults, transforms, etc.)
 * while integrating with the framework's env loader.
 */
function zodEnv<T extends z.ZodTypeAny>(schema: T): ValidateFn<z.infer<T>> {
  return (key: string, value?: string) => {
    const result = schema.safeParse(value)
    if (!result.success) {
      const messages = result.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join(', ')
      throw new Error(`Invalid environment variable "${key}": ${messages}`)
    }
    return result.data as z.infer<T>
  }
}

const booleanEnv = z.preprocess((value) => {
  if (value === undefined) return process.env.NODE_ENV !== 'production'
  if (typeof value === 'string') return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase())
  return value
}, z.boolean())

export default await Env.create(new URL('../', import.meta.url), {
  NODE_ENV: zodEnv(z.enum(['development', 'test', 'production']).default('development')),
  PORT: zodEnv(z.coerce.number().int().min(1).max(65535).default(8787)),
  HOST: zodEnv(z.string().default('0.0.0.0')),
  SERVICE_URL: zodEnv(z.string().url().default('http://localhost:8787')),
  DATABASE_PATH: zodEnv(z.string().default('./data/muvis.db')),
  DATABASE_AUTOMIGRATE: zodEnv(booleanEnv),
  JWT_SECRET: zodEnv(z.string().min(32).default(() => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('JWT_SECRET is required in production')
    }
    return 'dev-secret-do-not-use-in-production-' + Date.now()
  })),
  JWT_ACCESS_TTL_SECONDS: zodEnv(z.coerce.number().int().min(60).default(86400)),
  JWT_REFRESH_TTL_DAYS: zodEnv(z.coerce.number().int().min(1).default(7)),
  JWT_ISSUER: zodEnv(z.string().min(1).default('muvis')),
  JWT_AUDIENCE: zodEnv(z.string().min(1).default('m8.api')),
  APP_KEY: zodEnv(z.string().min(16).default(() => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('APP_KEY is required in production')
    }
    return 'dev-app-key-not-for-production'
  })),
  PLC_URL: zodEnv(z.string().url().default('https://plc.directory')),
  PDS_URL: zodEnv(z.string().url().default('https://bsky.social')),
  HANDLE_DOMAIN: zodEnv(z.string().optional()),
  PRIVATE_KEYS: zodEnv(z.string().optional()),
  COOKIE_SECRET: zodEnv(z.string().min(16).default(() => {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('COOKIE_SECRET is required in production')
    }
    return 'dev-cookie-secret-not-for-production'
  })),
  IDENTITY_ISSUER_DID: zodEnv(z.string().min(1).optional()),
  IDENTITY_ISSUER_PRIVATE_JWK: zodEnv(z.string().optional()),
  IDENTITY_ISSUER_PUBLIC_JWK: zodEnv(z.string().optional()),
  IDENTITY_ISSUER_KEY_ID: zodEnv(z.string().min(1).optional()),
  IDENTITY_ISSUER_PREVIOUS_PUBLIC_JWK: zodEnv(z.string().optional()),
  IDENTITY_ISSUER_PREVIOUS_KEY_ID: zodEnv(z.string().min(1).optional()),
  IDENTITY_ISSUER_PREVIOUS_KEY_EXPIRES_AT: zodEnv(z.string().datetime().optional()),
  IDENTITY_ISSUER_REVOKED_KEY_IDS: zodEnv(z.string().optional()),
  PARA_API_BASE_URL: zodEnv(z.string().url().optional()),
  PARA_API_TIMEOUT_MS: zodEnv(z.coerce.number().int().min(1000).default(5000)),
  GROWTHBOOK_API_HOST: zodEnv(z.string().url().optional()),
  GROWTHBOOK_CLIENT_KEY: zodEnv(z.string().optional()),
  GROWTHBOOK_INIT_TIMEOUT_MS: zodEnv(z.coerce.number().int().min(100).default(2000)),
  GROWTHBOOK_FEATURE_OVERRIDES: zodEnv(z.string().optional()),
  LOG_LEVEL: zodEnv(z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info')),
  CORS_ORIGIN: zodEnv(z.string().default('*')),
  RATE_LIMIT_ENABLED: zodEnv(booleanEnv),
  RATE_LIMIT_WINDOW_MS: zodEnv(z.coerce.number().int().min(1000).default(60000)),
  RATE_LIMIT_MAX: zodEnv(z.coerce.number().int().min(1).default(100)),
  RATE_LIMIT_AUTH_MAX: zodEnv(z.coerce.number().int().min(1).default(20)),
  RATE_LIMIT_COMMUNITY_READ_MAX: zodEnv(z.coerce.number().int().min(1).default(120)),
  RATE_LIMIT_COMMUNITY_MUTATION_MAX: zodEnv(z.coerce.number().int().min(1).default(20)),
  RATE_LIMIT_COMMUNITY_VOTE_MAX: zodEnv(z.coerce.number().int().min(1).default(30)),
  JSON_BODY_MAX_SIZE: zodEnv(z.string().default('1mb')),
  SECURITY_HEADERS_ENABLED: zodEnv(booleanEnv),
  BREAK_GLASS_DEMO_PATHS: zodEnv(z.enum(['enabled']).optional()),
})
