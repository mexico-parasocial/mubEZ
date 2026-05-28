import type { HttpContext } from '@adonisjs/core/http'

export default class HealthController {
  show({ response }: HttpContext) {
    return response.send({
      status: 'ok',
      service: 'Muvis',
      runtime: 'adonisjs',
      timestamp: new Date().toISOString(),
    })
  }
}
