import { z } from 'zod'
import type { HttpContext } from '@adonisjs/core/http'
import { getSessionId, validateBody } from '#support/http'
import { Features, isFeatureEnabled } from '../../src/services/features.js'
import {
  createPajareoEntry,
  createPajareoResponse,
  getRepresentativePajareoFeed,
  getViewerRepresentativePajareoFeed,
  reportPajareoEntry,
  supportPajareoEntry,
} from '../../src/services/pajareoService.js'

const entrySchema = z.object({
  type: z.enum(['firma', 'pregunta', 'señal', 'testimonio']),
  body: z.string().min(1).max(3000),
  subject: z.object({
    kind: z.enum(['person', 'institution', 'person_in_institution']),
    personId: z.string().max(200).nullable().optional(),
    personName: z.string().max(200).nullable().optional(),
    institutionId: z.string().max(200).nullable().optional(),
    institutionName: z.string().max(200).nullable().optional(),
  }).strict().optional(),
  jurisdiction: z.object({
    level: z.enum(['zone', 'state', 'nation', 'representative_area']),
    label: z.string().min(1).max(200),
  }).strict().optional(),
}).strict()

const responseSchema = z.object({
  body: z.string().min(1).max(3000),
}).strict()

const reportSchema = z.object({
  reason: z.string().max(500).optional(),
}).strict()

export default class PajareoController {
  async representative(ctx: HttpContext) {
    const representativeId = ctx.params.representativeId
    if (!isFeatureEnabled(Features.PajareoEnable)) {
      return ctx.response.send({ representativeId, entries: [] })
    }
    return ctx.response.send(getRepresentativePajareoFeed(representativeId))
  }

  async representativeMe(ctx: HttpContext) {
    const representativeId = ctx.params.representativeId
    if (!this.isMutationEnabled(ctx)) return

    return ctx.response.send(
      getViewerRepresentativePajareoFeed(getSessionId(ctx), representativeId),
    )
  }

  async createEntry(ctx: HttpContext) {
    if (!this.isMutationEnabled(ctx)) return
    const body = validateBody(ctx, entrySchema)
    if (!body) return

    return ctx.response.status(201).send({
      entry: createPajareoEntry(getSessionId(ctx), {
        representativeId: ctx.params.representativeId,
        type: body.type,
        body: body.body,
        subject: body.subject,
        jurisdiction: body.jurisdiction,
      }),
    })
  }

  async createResponse(ctx: HttpContext) {
    if (!this.isMutationEnabled(ctx)) return
    const body = validateBody(ctx, responseSchema)
    if (!body) return

    return ctx.response.status(201).send({
      response: createPajareoResponse(getSessionId(ctx), ctx.params.entryId, {
        body: body.body,
      }),
    })
  }

  async support(ctx: HttpContext) {
    if (!this.isMutationEnabled(ctx)) return

    return ctx.response.send({
      entry: supportPajareoEntry(getSessionId(ctx), ctx.params.entryId),
    })
  }

  async report(ctx: HttpContext) {
    if (!this.isMutationEnabled(ctx)) return
    const body = validateBody(ctx, reportSchema)
    if (!body) return

    return ctx.response.send({
      entry: reportPajareoEntry(getSessionId(ctx), ctx.params.entryId, body.reason),
    })
  }

  private isMutationEnabled(ctx: HttpContext) {
    if (isFeatureEnabled(Features.PajareoEnable)) return true

    ctx.response.status(404).send({
      error: 'Pajareo is disabled',
      code: 'FEATURE_DISABLED',
    })
    return false
  }
}
