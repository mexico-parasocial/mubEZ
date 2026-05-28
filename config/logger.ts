import { defineConfig, syncDestination, targets } from '@adonisjs/core/logger'
import type { LoggerConfig } from '@adonisjs/logger/types'
import app from '@adonisjs/core/services/app'
import env from '#start/env'

const loggerConfig = defineConfig<{ app: LoggerConfig }>({
  default: 'app',
  loggers: {
    app: {
      enabled: true,
      name: 'muvis',
      level: env.get('LOG_LEVEL'),
      destination: !app.inProduction ? await syncDestination() : undefined,
      transport: {
        targets: [targets.file({ destination: 1 })],
      },
    },
  },
})

export default loggerConfig
