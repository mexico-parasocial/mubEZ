import { defineConfig } from '@adonisjs/core/bodyparser'
import type { BodyParserConfig } from '@adonisjs/bodyparser/types'
import env from '#start/env'

const bodyParserConfig: BodyParserConfig = defineConfig({
  allowedMethods: ['POST', 'PUT', 'PATCH', 'DELETE'],
  form: {
    convertEmptyStringsToNull: true,
    types: ['application/x-www-form-urlencoded'],
    limit: env.get('JSON_BODY_MAX_SIZE'),
  },
  json: {
    convertEmptyStringsToNull: true,
    types: ['application/json', 'application/json-patch+json', 'application/vnd.api+json'],
    limit: env.get('JSON_BODY_MAX_SIZE'),
  },
  multipart: {
    autoProcess: true,
    convertEmptyStringsToNull: true,
    processManually: [],
    limit: '20mb',
    types: ['multipart/form-data'],
  },
})

export default bodyParserConfig
