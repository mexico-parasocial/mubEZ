import router from '@adonisjs/core/services/router'
import server from '@adonisjs/core/services/server'

server.errorHandler(() => import('#exceptions/handler'))

server.use([
  () => import('#middleware/security_headers_middleware'),
  () => import('#middleware/rate_limit_middleware'),
  () => import('#middleware/force_json_response_middleware'),
  () => import('#middleware/container_bindings_middleware'),
  () => import('@adonisjs/cors/cors_middleware'),
  () => import('#middleware/abuse_monitor_middleware'),
])

router.use([() => import('@adonisjs/core/bodyparser_middleware')])

export const middleware: Record<string, (...args: any[]) => any> = router.named({
  auth: () => import('#middleware/auth_middleware'),
})
