'use strict'

import errors = require('../errors')
import type { ErrorSpec } from '../errors/types'

const spec: ErrorSpec = {
  name: 'ECIES',
  message: 'Internal Error on bsv-ecies Module {0}',
  errors: [{
    name: 'DecryptionError',
    message: 'Invalid Message: {0}'
  },
  {
    name: 'UnsupportAlgorithm',
    message: 'Unsupport Algorithm: {0}'
  }]
}

export = errors.extend(spec)
