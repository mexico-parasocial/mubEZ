import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import {
  issueCivicVoteProof,
  linkCivicVoteAlias,
} from '../../src/services/civicVoteIdentityService.js'

const subjectTypeSchema = z.enum([
  'cabildeo',
  'policy',
  'matter',
  'governance',
  'raq_axis',
  'raq_proposal',
  'community_proposal',
  'community_deliberation',
  'open_question_reply',
])

const proofSchema = z
  .object({
    subjectUri: z.string().min(1).max(1024),
    subjectType: subjectTypeSchema,
    aliasDid: z.string().min(1).max(512).optional(),
  })
  .strict()

const aliasSchema = z
  .object({
    did: z.string().min(1).max(512),
    handle: z.string().max(512).optional(),
  })
  .strict()

export default class CivicVoteIdentityController {
  async issueProof(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, proofSchema)
    if (!body) return
    return ctx.response.send({ proof: issueCivicVoteProof(sessionId, body) })
  }

  async linkAlias(ctx: HttpContext) {
    const sessionId = getSessionId(ctx)
    const body = validateBody(ctx, aliasSchema)
    if (!body) return
    return ctx.response.send({ alias: linkCivicVoteAlias(sessionId, body) })
  }
}
