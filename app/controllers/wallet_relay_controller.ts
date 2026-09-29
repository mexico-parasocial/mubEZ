import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  collectIssuedCredentials,
  createWalletBindingRequest,
  declineWalletBindingRequest,
  fulfillWalletBindingRequest,
  getWalletBindingRequest,
  listWalletBindingRequests,
} from '../../src/services/walletRelayService.js'

const fulfillSchema = z.object({
  holderPublicKey: z.string().min(1).max(1024),
  holderKeyProof: z.string().min(1).max(256),
}).strict()

/**
 * Session-bound relay between PARA (needs a holder binding for an INE
 * issuance) and the iM8 wallet (holds the key). See walletRelayService.ts.
 */
export default class WalletRelayController {
  /** PARA: ask the wallet for a holder binding. */
  async store(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    try {
      return ctx.response.status(201).send(createWalletBindingRequest(sessionId))
    } catch (error) {
      return ctx.response.status(429).send({
        error: error instanceof Error ? error.message : 'Too many open binding requests',
        code: 'WALLET_BINDING_LIMIT',
      })
    }
  }

  /** Wallet: pending bindings and issued credentials waiting to be collected. */
  async index(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    return ctx.response.send({ requests: listWalletBindingRequests(sessionId) })
  }

  /** PARA's poll. */
  async show(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const request = getWalletBindingRequest(sessionId, ctx.params.id)
    if (!request) {
      return ctx.response.status(404).send({ error: 'Binding request not found or expired' })
    }
    return ctx.response.send(request)
  }

  /** Wallet: public key and proof of possession, never the private key. */
  async fulfill(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, fulfillSchema)
    if (!body) return
    const result = fulfillWalletBindingRequest(sessionId, ctx.params.id, body)
    if (!result.ok) {
      return ctx.response.status(result.reason === 'not-found' ? 404 : 400).send({ error: result.reason })
    }
    return ctx.response.send({ status: 'bound' })
  }

  async decline(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const result = declineWalletBindingRequest(sessionId, ctx.params.id)
    if (!result.ok) {
      return ctx.response.status(result.reason === 'not-found' ? 404 : 400).send({ error: result.reason })
    }
    return ctx.response.send({ status: 'declined' })
  }

  /** Wallet: the issued credentials, returned once and erased from the relay. */
  async collect(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const delivery = collectIssuedCredentials(sessionId, ctx.params.id)
    if (!delivery) {
      return ctx.response.status(404).send({ error: 'No issued credentials waiting for this request' })
    }
    return ctx.response.send(delivery)
  }
}
