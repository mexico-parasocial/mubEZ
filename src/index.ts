import { createServer, type Server } from 'node:http'

type InjectOptions = {
  method: string
  url: string
  headers?: Record<string, string>
  payload?: unknown
}

export type AdonisTestApp = {
  inject(options: InjectOptions): Promise<{ statusCode: number; payload: string; headers: Record<string, string> }>
  close(): Promise<void>
}

function pickTestPort() {
  return String(18000 + Math.floor(Math.random() * 20000))
}

export async function buildApp(): Promise<AdonisTestApp> {
  process.env.HOST = process.env.HOST || '127.0.0.1'
  process.env.PORT = process.env.PORT || pickTestPort()

  await import('reflect-metadata')
  const { assertProductionFeatureSafety, featureFlagsReady } = await import('./services/features.js')
  await featureFlagsReady
  assertProductionFeatureSafety()
  const { Ignitor } = await import('@adonisjs/core')
  const appRoot = new URL('../', import.meta.url)
  let nodeServer: Server | null = null

  const importer = (filePath: string) => {
    if (filePath.startsWith('./') || filePath.startsWith('../')) {
      return import(new URL(filePath, appRoot).href)
    }
    return import(filePath)
  }

  const ignitor = new Ignitor(appRoot, { importer })
  await ignitor.httpServer().start((handler) => {
    nodeServer = createServer(handler)
    return nodeServer
  })

  const activeServer = nodeServer as Server | null
  const address = activeServer?.address()
  const port = typeof address === 'object' && address ? address.port : Number(process.env.PORT)
  const host = process.env.HOST === '0.0.0.0' ? '127.0.0.1' : process.env.HOST
  const baseUrl = `http://${host}:${port}`

  return {
    async inject(options) {
      const headers = new Headers(options.headers)
      let body: string | undefined

      if (options.payload !== undefined) {
        body = typeof options.payload === 'string' ? options.payload : JSON.stringify(options.payload)
        if (!headers.has('content-type')) headers.set('content-type', 'application/json')
      }

      const response = await fetch(new URL(options.url, baseUrl), {
        method: options.method,
        headers,
        body,
      })

      return {
        statusCode: response.status,
        payload: await response.text(),
        headers: Object.fromEntries(response.headers.entries()),
      }
    },

    async close() {
      await ignitor.terminate()
    },
  }
}
