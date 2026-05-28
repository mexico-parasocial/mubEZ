import { defineConfig } from '@adonisjs/cors'
import env from '#start/env'

const corsOrigin = env.get('CORS_ORIGIN')
const origin =
  corsOrigin === '*'
    ? true
    : corsOrigin.split(',')
        .map((value: string) => value.trim())
        .filter(Boolean)

export default defineConfig({
  enabled: true,
  origin,
  methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  headers: ['content-type', 'authorization', 'x-m8-session-id'],
  exposeHeaders: [],
  credentials: true,
  maxAge: 90,
})
