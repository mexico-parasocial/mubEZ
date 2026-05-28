export {}

declare module '@adonisjs/core/http' {
  interface HttpContext {
    /**
     * Authenticated session ID. Populated by the auth middleware
     * on protected routes.
     */
    sessionId?: string
  }
}
