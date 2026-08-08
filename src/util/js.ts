'use strict'

import _ = require('../util/_')
import $ = require('./preconditions')

/**
 * Determines whether a string contains only hexadecimal values.
 */
const isHexa = function isHexa (value: unknown): boolean {
  if (!_.isString(value)) {
    return false
  }
  return /^[0-9a-fA-F]+$/.test(value)
}

const JSUtil = {
  /**
   * Test if an argument is a valid JSON object.
   *
   * NOTE: despite the name and the original JSDoc ("returns the json object
   * decoded"), this returns a boolean — it reports whether the parse produced
   * an object, and discards the result. Preserved as-is; changing it would be
   * an API change, and callers currently rely on the boolean.
   */
  isValidJSON: function isValidJSON (arg: unknown): boolean {
    let parsed: unknown
    if (!_.isString(arg)) {
      return false
    }
    try {
      parsed = JSON.parse(arg)
    } catch (e) {
      return false
    }
    return typeof parsed === 'object'
  },

  isHexa,
  isHexaString: isHexa,

  /** Define immutable, enumerable properties on a target object. */
  defineImmutable: function defineImmutable<T extends object> (
    target: T,
    values: Record<string, unknown>
  ): T {
    Object.keys(values).forEach(function (key) {
      Object.defineProperty(target, key, {
        configurable: false,
        enumerable: true,
        value: values[key]
      })
    })
    return target
  },

  /** A positive integer or zero. */
  isNaturalNumber: function isNaturalNumber (value: unknown): boolean {
    return typeof value === 'number' &&
      isFinite(value) &&
      Math.floor(value) === value &&
      value >= 0
  },

  /** A 4-byte unsigned integer as a big-endian Buffer. */
  integerAsBuffer: function integerAsBuffer (integer: number): Buffer {
    $.checkArgumentType(integer, 'number', 'integer')
    const buf = Buffer.allocUnsafe(4)
    buf.writeUInt32BE(integer, 0)
    return buf
  }
}

export = JSUtil
