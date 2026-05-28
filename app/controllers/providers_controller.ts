import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId } from '#support/http'
import { resolveParaProviderStatus } from '../../src/services/paraProvider.js'

export default class ProvidersController {
  async paraStatus(ctx: HttpContext) {
    getSessionId(ctx)
    return ctx.response.send(await resolveParaProviderStatus())
  }
}
