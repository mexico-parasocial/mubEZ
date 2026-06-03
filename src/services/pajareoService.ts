import { randomUUID } from 'node:crypto'
import { getDb } from '../db/connection.js'
import { ensurePajareoIdentity, linkAnonymousPost } from './anonymousIdentityService.js'

export type PajareoEntryType = 'firma' | 'pregunta' | 'señal' | 'testimonio'
export type PajareoResponseKind = 'public' | 'official'
export type PajareoSubjectKind = 'person' | 'institution' | 'person_in_institution'
export type PajareoJurisdictionLevel = 'zone' | 'state' | 'nation' | 'representative_area'

export interface PajareoSubject {
  kind: PajareoSubjectKind
  personId: string | null
  personName: string | null
  institutionId: string | null
  institutionName: string | null
}

export interface PajareoJurisdiction {
  level: PajareoJurisdictionLevel
  label: string
}

export interface PajareoOfficialResponse {
  id: string
  entryId: string
  representativeId: string
  entityId: string
  entityName: string
  body: string
  controllerHash: string
  createdAt: string
}

export interface PajareoResponse {
  id: string
  entryId: string
  representativeId: string
  kind: PajareoResponseKind
  responderDid: string
  responderDisplayName: string | null
  entityId: string | null
  entityName: string | null
  body: string
  controllerHash: string | null
  createdAt: string
}

export interface PajareoEntry {
  id: string
  representativeId: string
  subject: PajareoSubject
  jurisdiction: PajareoJurisdiction
  type: PajareoEntryType
  body: string
  anonymousDisplayArea: string
  supportCount: number
  reportCount: number
  responseCount: number
  questionAnswered: boolean
  officialResponse?: PajareoOfficialResponse
  responses: PajareoResponse[]
  status: 'visible' | 'removed'
  createdAt: string
  updatedAt: string
}

export interface PajareoEligibility {
  representativeId: string
  eligible: boolean
  reason: 'eligible' | 'representative_not_verified'
  areaLabel: string
}

export interface PajareoIdentitySummary {
  id: string
  displayName: string
  surface: 'civic'
  communityUri: 'm8:pajareo'
}

export interface PajareoFeed {
  representativeId: string
  entries: PajareoEntry[]
  eligibility?: PajareoEligibility
  pajareoIdentity?: PajareoIdentitySummary
}

const REPRESENTATIVE_AREAS: Record<string, string> = {
  fed_exec_1: 'México',
  gov_nl_1: 'Nuevo León',
  party_morena_president_2026: 'México',
}

const OFFICIAL_CONTROLLERS: Record<string, Array<{
  entityId: string
  entityName: string
  controllerDid: string
  scopes: string[]
  status: 'active' | 'revoked'
}>> = {
  fed_exec_1: [
    {
      entityId: 'official:representative:fed_exec_1',
      entityName: 'Presidencia de México',
      controllerDid: 'did:plc:alice',
      scopes: ['official.pajareo.respond'],
      status: 'active',
    },
  ],
  gov_nl_1: [
    {
      entityId: 'official:representative:gov_nl_1',
      entityName: 'Gobierno de Nuevo León',
      controllerDid: 'did:plc:alice',
      scopes: ['official.pajareo.respond'],
      status: 'active',
    },
  ],
}

export function getRepresentativePajareoFeed(representativeId: string): PajareoFeed {
  return {
    representativeId,
    entries: listEntries(representativeId),
  }
}

export function getViewerRepresentativePajareoFeed(sessionId: string, representativeId: string): PajareoFeed {
  const identity = ensurePajareoIdentity(sessionId)
  return {
    representativeId,
    entries: listEntries(representativeId),
    eligibility: {
      representativeId,
      eligible: true,
      reason: 'eligible',
      areaLabel: areaLabelForRepresentative(representativeId),
    },
    pajareoIdentity: {
      id: identity.id,
      displayName: identity.displayName,
      surface: 'civic',
      communityUri: 'm8:pajareo',
    },
  }
}

export function createPajareoEntry(sessionId: string, input: {
  representativeId: string
  type: PajareoEntryType
  body: string
  subject?: Partial<PajareoSubject>
  jurisdiction?: Partial<PajareoJurisdiction>
}): PajareoEntry {
  const db = getDb()
  const identity = ensurePajareoIdentity(sessionId)
  const id = `pajareo-${randomUUID()}`
  const now = new Date().toISOString()
  const areaLabel = areaLabelForRepresentative(input.representativeId)
  const subject = normalizeSubject(input.representativeId, input.subject)
  const jurisdiction = normalizeJurisdiction(areaLabel, input.jurisdiction)

  db.prepare(`
    INSERT INTO pajareo_entries
      (id, representative_id, subject_kind, subject_id, subject_name, institution_id, institution_name, jurisdiction_level, jurisdiction_label, anonymous_identity_id, entry_type, body, anonymous_display_area, status, support_count, report_count, response_count, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'visible', ?, 0, 0, ?, ?)
  `).run(
    id,
    input.representativeId,
    subject.kind,
    subject.personId,
    subject.personName,
    subject.institutionId,
    subject.institutionName,
    jurisdiction.level,
    jurisdiction.label,
    identity.id,
    input.type,
    input.body,
    `Persona verificada de ${jurisdiction.label}`,
    input.type === 'firma' ? 1 : 0,
    now,
    now,
  )

  linkAnonymousPost(sessionId, {
    identityId: identity.id,
    postUri: pajareoPostUri(id),
    communityUri: 'm8:pajareo',
    postType: 'pajareo.entry',
  })
  writeLedger(sessionId, 'PajareoEntryCreated', 'pajareo_entry', id, {
    representativeId: input.representativeId,
    type: input.type,
    subject,
    jurisdiction,
  })

  return requireEntry(id)
}

export function createPajareoResponse(sessionId: string, entryId: string, input: {
  body: string
}): PajareoResponse {
  const db = getDb()
  const entry = requireEntryRow(entryId)
  const session = requireSession(sessionId)
  const officialController = findOfficialController(entry.representative_id as string, session.did)
  const id = `pajareo-response-${randomUUID()}`
  const now = new Date().toISOString()
  const kind: PajareoResponseKind = officialController ? 'official' : 'public'

  db.prepare(`
    INSERT INTO pajareo_responses
      (id, entry_id, responder_session_id, responder_did, responder_display_name, response_kind, official_entity_id, official_entity_name, official_controller_hash, body, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    entryId,
    sessionId,
    session.did,
    session.displayName,
    kind,
    officialController?.entityId ?? null,
    officialController?.entityName ?? null,
    officialController ? hashController(session.did) : null,
    input.body,
    now,
  )
  db.prepare(`
    UPDATE pajareo_entries
    SET response_count = response_count + 1, updated_at = ?
    WHERE id = ?
  `).run(now, entryId)
  writeLedger(sessionId, 'PajareoResponseCreated', 'pajareo_response', id, {
    entryId,
    responseKind: kind,
  })

  return mapResponse(requireResponseRow(id), entry.representative_id as string)
}

export function supportPajareoEntry(sessionId: string, entryId: string): PajareoEntry {
  const db = getDb()
  requireEntryRow(entryId)
  const inserted = db.prepare(`
    INSERT OR IGNORE INTO pajareo_entry_supports (entry_id, session_id, created_at)
    VALUES (?, ?, ?)
  `).run(entryId, sessionId, new Date().toISOString()).changes
  if (inserted > 0) {
    db.prepare(`
      UPDATE pajareo_entries
      SET support_count = support_count + 1, updated_at = ?
      WHERE id = ?
    `).run(new Date().toISOString(), entryId)
    writeLedger(sessionId, 'PajareoEntrySupported', 'pajareo_entry', entryId, {})
  }
  return requireEntry(entryId)
}

export function reportPajareoEntry(sessionId: string, entryId: string, reason?: string): PajareoEntry {
  const db = getDb()
  requireEntryRow(entryId)
  const inserted = db.prepare(`
    INSERT OR IGNORE INTO pajareo_entry_reports (entry_id, session_id, reason, created_at)
    VALUES (?, ?, ?, ?)
  `).run(entryId, sessionId, reason ?? null, new Date().toISOString()).changes
  if (inserted > 0) {
    db.prepare(`
      UPDATE pajareo_entries
      SET report_count = report_count + 1, updated_at = ?
      WHERE id = ?
    `).run(new Date().toISOString(), entryId)
    writeLedger(sessionId, 'PajareoEntryReported', 'pajareo_entry', entryId, { reason: reason ?? null })
  }
  return requireEntry(entryId)
}

function listEntries(representativeId: string): PajareoEntry[] {
  const rows = getDb().prepare(`
    SELECT * FROM pajareo_entries
    WHERE representative_id = ? AND status = 'visible'
    ORDER BY created_at DESC
  `).all(representativeId) as Record<string, unknown>[]
  return rows.map(mapEntry)
}

function requireEntry(entryId: string): PajareoEntry {
  return mapEntry(requireEntryRow(entryId))
}

function requireEntryRow(entryId: string): Record<string, unknown> {
  const row = getDb().prepare('SELECT * FROM pajareo_entries WHERE id = ?').get(entryId) as Record<string, unknown> | undefined
  if (!row) throw appError('Pajareo entry not found', 404, 'PAJAREO_ENTRY_NOT_FOUND')
  return row
}

function requireResponseRow(responseId: string): Record<string, unknown> {
  const row = getDb().prepare('SELECT * FROM pajareo_responses WHERE id = ?').get(responseId) as Record<string, unknown> | undefined
  if (!row) throw appError('Pajareo response not found', 404, 'PAJAREO_RESPONSE_NOT_FOUND')
  return row
}

function mapEntry(row: Record<string, unknown>): PajareoEntry {
  const representativeId = row.representative_id as string
  const subjectKind = (row.subject_kind as PajareoSubjectKind | undefined) ?? 'person'
  const responses = getDb().prepare(`
    SELECT * FROM pajareo_responses
    WHERE entry_id = ?
    ORDER BY created_at ASC
  `).all(row.id as string) as Record<string, unknown>[]
  const mappedResponses = responses.map((response) => mapResponse(response, representativeId))
  const officialResponse = mappedResponses.find((response) => response.kind === 'official')

  return {
    id: row.id as string,
    representativeId,
    subject: {
      kind: subjectKind,
      personId: (row.subject_id as string | null | undefined) ?? (subjectKind === 'institution' ? null : representativeId),
      personName: (row.subject_name as string | null | undefined) ?? null,
      institutionId: (row.institution_id as string | null | undefined) ?? null,
      institutionName: (row.institution_name as string | null | undefined) ?? null,
    },
    jurisdiction: {
      level: (row.jurisdiction_level as PajareoJurisdictionLevel | undefined) ?? 'representative_area',
      label: (row.jurisdiction_label as string | undefined) ?? areaLabelForRepresentative(representativeId),
    },
    type: row.entry_type as PajareoEntryType,
    body: row.body as string,
    anonymousDisplayArea: row.anonymous_display_area as string,
    supportCount: Number(row.support_count ?? 0),
    reportCount: Number(row.report_count ?? 0),
    responseCount: Number(row.response_count ?? mappedResponses.length),
    questionAnswered: Boolean(officialResponse),
    officialResponse: officialResponse
      ? {
          id: officialResponse.id,
          entryId: officialResponse.entryId,
          representativeId,
          entityId: officialResponse.entityId ?? '',
          entityName: officialResponse.entityName ?? 'Entidad oficial',
          body: officialResponse.body,
          controllerHash: officialResponse.controllerHash ?? '',
          createdAt: officialResponse.createdAt,
        }
      : undefined,
    responses: mappedResponses,
    status: row.status as 'visible' | 'removed',
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
  }
}

function mapResponse(row: Record<string, unknown>, representativeId: string): PajareoResponse {
  return {
    id: row.id as string,
    entryId: row.entry_id as string,
    representativeId,
    kind: row.response_kind as PajareoResponseKind,
    responderDid: row.responder_did as string,
    responderDisplayName: row.responder_display_name as string | null,
    entityId: row.official_entity_id as string | null,
    entityName: row.official_entity_name as string | null,
    body: row.body as string,
    controllerHash: row.official_controller_hash as string | null,
    createdAt: row.created_at as string,
  }
}

function normalizeSubject(
  representativeId: string,
  subject?: Partial<PajareoSubject>,
): PajareoSubject {
  const kind = subject?.kind ?? 'person'
  const explicitPersonId = normalizeNullableText(subject?.personId)
  const explicitPersonName = normalizeNullableText(subject?.personName)
  const explicitInstitutionId = normalizeNullableText(subject?.institutionId)
  const explicitInstitutionName = normalizeNullableText(subject?.institutionName)
  const personId = explicitPersonId ?? (kind === 'institution' ? null : representativeId)

  if (kind === 'institution') {
    return {
      kind,
      personId: null,
      personName: null,
      institutionId: explicitInstitutionId,
      institutionName: explicitInstitutionName,
    }
  }

  if (kind === 'person_in_institution') {
    return {
      kind,
      personId,
      personName: explicitPersonName,
      institutionId: explicitInstitutionId,
      institutionName: explicitInstitutionName,
    }
  }

  return {
    kind: 'person',
    personId,
    personName: explicitPersonName,
    institutionId: null,
    institutionName: null,
  }
}

function normalizeNullableText(value: string | null | undefined) {
  const trimmed = value?.trim()
  return trimmed ? trimmed : null
}

function normalizeJurisdiction(
  representativeAreaLabel: string,
  jurisdiction?: Partial<PajareoJurisdiction>,
): PajareoJurisdiction {
  const level = jurisdiction?.level ?? 'representative_area'
  const label = jurisdiction?.label?.trim() || (level === 'nation' ? 'México' : representativeAreaLabel)
  return { level, label }
}

function areaLabelForRepresentative(representativeId: string) {
  return REPRESENTATIVE_AREAS[representativeId] ?? 'México'
}

function findOfficialController(representativeId: string, did: string) {
  return OFFICIAL_CONTROLLERS[representativeId]?.find(
    (controller) =>
      controller.status === 'active' &&
      controller.controllerDid === did &&
      controller.scopes.includes('official.pajareo.respond'),
  )
}

function requireSession(sessionId: string): { did: string; displayName: string } {
  const row = getDb().prepare('SELECT did, display_name FROM sessions WHERE session_id = ?').get(sessionId) as { did: string; display_name: string } | undefined
  if (!row) throw appError('Session not found', 404, 'SESSION_NOT_FOUND')
  return {
    did: row.did,
    displayName: row.display_name,
  }
}

function pajareoPostUri(entryId: string) {
  return `m8://pajareo/entries/${entryId}`
}

function hashController(controllerDid: string) {
  let hash = 0
  for (let i = 0; i < controllerDid.length; i++) {
    hash = (hash << 5) - hash + controllerDid.charCodeAt(i)
    hash |= 0
  }
  return `ctrl_${Math.abs(hash).toString(16).padStart(8, '0')}`
}

function writeLedger(sessionId: string, action: string, targetType: string, targetId: string, detail: unknown) {
  getDb().prepare(`
    INSERT INTO ledger (session_id, action, target_type, target_id, detail_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(sessionId, action, targetType, targetId, JSON.stringify(detail ?? {}), new Date().toISOString())
}

function appError(message: string, statusCode: number, code: string) {
  return Object.assign(new Error(message), { statusCode, code })
}
