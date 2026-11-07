import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  AGE_TREE_CHUNK_SIZE,
  AGE_TREE_DEPTH,
  AGE_TREE_ROOT_WINDOW_MS,
  AgeTreeError,
  acceptableAgeTreeRoots,
  ageTreeChunk,
  ageTreeChunkRoots,
  parseLeafCommitment,
  refreshAgeLeaf,
  syncAgeTree,
} from '../../src/services/ageTree.js'

const dayInt = z.number().int().min(0).max(1_000_000)

const refreshSchema = z.object({
  leafIndex: z.number().int().min(0),
  leafCommitment: z.string().min(1).max(80),
  birthDay: dayInt,
  expiryDay: dayInt,
}).strict()

function sendAgeTreeError(ctx: HttpContext, error: unknown) {
  if (error instanceof AgeTreeError) {
    return ctx.response.status(error.status).send({ error: error.message, code: error.code })
  }
  throw error
}

/**
 * The issuer age tree (ageTree.ts). Everything but refresh is public and
 * session-free: a wallet reading its chunk, or a verifier checking a root,
 * must not have to say who it is.
 */
export default class AgeTreeController {
  /** The current signed root. */
  async root(ctx: HttpContext) {
    try {
      const root = await syncAgeTree()
      if (!root) {
        return ctx.response.status(503).send({ error: 'The age tree has not been published yet', code: 'AGE_TREE_UNSIGNED' })
      }
      return ctx.response.send(root)
    } catch (error) {
      return sendAgeTreeError(ctx, error)
    }
  }

  /** Every root a verifier should accept now, newest first. */
  async roots(ctx: HttpContext) {
    try {
      return ctx.response.send({
        depth: AGE_TREE_DEPTH,
        chunkSize: AGE_TREE_CHUNK_SIZE,
        windowSeconds: AGE_TREE_ROOT_WINDOW_MS / 1000,
        roots: await acceptableAgeTreeRoots(),
      })
    } catch (error) {
      return sendAgeTreeError(ctx, error)
    }
  }

  async chunk(ctx: HttpContext) {
    const raw = String(ctx.params.chunk)
    const chunk = /^[0-9]{1,7}$/.test(raw) ? Number(raw) : Number.NaN
    try {
      return ctx.response.send(await ageTreeChunk(chunk))
    } catch (error) {
      return sendAgeTreeError(ctx, error)
    }
  }

  async chunkRoots(ctx: HttpContext) {
    try {
      return ctx.response.send(await ageTreeChunkRoots())
    } catch (error) {
      return sendAgeTreeError(ctx, error)
    }
  }

  /** Re-issue the caller's leaf with a fresh expiry, on proof of its preimage. */
  async refresh(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, refreshSchema)
    if (!body) return
    const leafCommitment = parseLeafCommitment(body.leafCommitment)
    if (leafCommitment === null) {
      return ctx.response.status(400).send({ error: 'leafCommitment must be a non-zero BN254 field element', code: 'AGE_LEAF_COMMITMENT_INVALID' })
    }
    try {
      const leaf = await refreshAgeLeaf(sessionId, { ...body, leafCommitment })
      return ctx.response.send(leaf)
    } catch (error) {
      return sendAgeTreeError(ctx, error)
    }
  }
}
