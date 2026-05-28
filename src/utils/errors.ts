/**
 * Create an application error with HTTP status code and error code.
 *
 * Used by services to signal domain errors that the global exception handler
 * converts into structured HTTP responses.
 */
export function appError(message: string, statusCode: number, code: string) {
  return Object.assign(new Error(message), { statusCode, code })
}
