import type { HttpContext } from '@adonisjs/core/http'
import { getIssuerMetadata } from '../../src/services/identityWallet.js'

export default class IssuersController {
  index({ response }: HttpContext) {
    return response.send(getIssuerMetadata())
  }
}
