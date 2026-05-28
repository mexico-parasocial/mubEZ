/**
 * Return the current time as an ISO-8601 string.
 *
 * Centralised so the entire codebase uses the same timestamp format.
 */
export function nowIso() {
  return new Date().toISOString()
}
