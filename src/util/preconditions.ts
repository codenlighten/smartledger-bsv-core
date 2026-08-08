'use strict'

import errors = require('../errors')
import _ = require('../util/_')

/**
 * Argument and state guards used throughout the library.
 *
 * The error constructors are reached off the dynamically built error tree, so
 * they are narrowed from its index signature at the point of use rather than
 * being statically nameable. See errors/types for why that tree cannot be
 * precisely typed without duplicating the spec.
 */

type ErrCtor = new (...args: unknown[]) => Error
const err = (name: string): ErrCtor => errors[name] as ErrCtor

const preconditions = {
  checkState: function (condition: unknown, message?: string): void {
    if (condition === false || condition == null || condition === 0 || condition === '') {
      throw new (err('InvalidState'))(message)
    }
  },

  checkArgument: function (
    condition: unknown,
    // Callers pass an Error here as well as a string (see crypto/bn's
    // script-number overflow check); the error formatter stringifies it.
    argumentName?: unknown,
    message?: string,
    docsPath?: string
  ): void {
    if (condition === false || condition == null || condition === 0 || condition === '') {
      throw new (err('InvalidArgument'))(argumentName, message, docsPath)
    }
  },

  checkArgumentType: function (
    argument: unknown,
    type: string | (new (...args: never[]) => unknown),
    argumentName?: string
  ): void {
    const name = argumentName ?? '(unknown name)'
    if (_.isString(type)) {
      if (type === 'Buffer') {
        if (!Buffer.isBuffer(argument)) {
          throw new (err('InvalidArgumentType'))(argument, type, name)
        }
      } else if (typeof argument !== type) {
        throw new (err('InvalidArgumentType'))(argument, type, name)
      }
    } else {
      if (!(argument instanceof type)) {
        throw new (err('InvalidArgumentType'))(argument, type.name, name)
      }
    }
  }
}

export = preconditions
