import app from '@adonisjs/core/services/app'
import { defineConfig } from '@adonisjs/core/http'
import env from '#start/env'

export const appKey = env.get('APP_KEY')
export const appUrl = env.get('SERVICE_URL')

// AdonisJS's default trustProxy is proxy-addr's "loopback": request.ip()
// walks x-forwarded-for from any client connecting over 127.0.0.1, so a
// forged header sets the IP that rate limiting and abuse records key on.
// Trust proxy headers only when the deployment declares a local reverse
// proxy; otherwise trust nothing and use the socket address.
const trustProxyHeaders = env.get('TRUST_PROXY_HEADERS')

export const http = defineConfig({
  generateRequestId: true,
  ...(trustProxyHeaders ? {} : { trustProxy: false }),
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
