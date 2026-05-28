import app from '@adonisjs/core/services/app'
import { defineConfig } from '@adonisjs/core/http'
import env from '#start/env'

export const appKey = env.get('APP_KEY')
export const appUrl = env.get('SERVICE_URL')

export const http = defineConfig({
  generateRequestId: true,
  allowMethodSpoofing: false,
  useAsyncLocalStorage: true,
  redirect: {
    forwardQueryString: true,
  },
  cookie: {
    domain: '',
    path: '/',
    maxAge: '2h',
    httpOnly: true,
    secure: app.inProduction,
    sameSite: 'lax',
  },
})
