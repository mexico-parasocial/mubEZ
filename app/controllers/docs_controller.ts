import { readFileSync } from 'node:fs'
import type { HttpContext } from '@adonisjs/core/http'

const openApiPath = new URL('../../src/openapi/openapi.json', import.meta.url)

export default class DocsController {
  openapi({ response }: HttpContext) {
    const spec = readFileSync(openApiPath, 'utf8')
    return response.header('content-type', 'application/json; charset=utf-8').send(spec)
  }

  scalar({ response }: HttpContext) {
    return response.header('content-type', 'text/html; charset=utf-8').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Muvis API</title>
    <script id="api-reference" data-url="/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </head>
  <body></body>
</html>`)
  }
}
