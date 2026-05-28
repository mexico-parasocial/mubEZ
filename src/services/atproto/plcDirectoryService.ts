import env from '#start/env'
import { appError } from '../../utils/errors.js'

export type PlcAuditEntry = {
  cid?: string
  nullified?: boolean
  operation: Record<string, unknown>
}

export async function getPlcAuditLogs(did: string): Promise<PlcAuditEntry[]> {
  if (!did.startsWith('did:plc:')) {
    throw appError('PLC audit logs are only available for did:plc identifiers', 422, 'NOT_PLC_DID')
  }

  const base = env.get('PLC_URL').replace(/\/$/, '')
  const response = await fetch(`${base}/${did}/log/audit`, {
    headers: { accept: 'application/json' },
  })

  if (!response.ok) {
    throw appError('Could not resolve PLC audit logs', response.status, 'PLC_AUDIT_LOGS_FAILED')
  }

  const logs = await response.json()
  if (!Array.isArray(logs)) {
    throw appError('PLC audit logs response was invalid', 502, 'PLC_AUDIT_LOGS_INVALID')
  }

  return logs as PlcAuditEntry[]
}

export function getLastPlcOperation(logs: PlcAuditEntry[]): { operation: Record<string, unknown>; base: PlcAuditEntry } | null {
  const last = logs.at(-1)
  if (!last) return null
  return {
    operation: last.operation,
    base: last,
  }
}

export async function getCurrentRotationKeys(did: string): Promise<string[]> {
  const logs = await getPlcAuditLogs(did)
  const last = getLastPlcOperation(logs)
  const rotationKeys = last?.operation.rotationKeys
  return Array.isArray(rotationKeys) ? rotationKeys.filter((key): key is string => typeof key === 'string') : []
}
