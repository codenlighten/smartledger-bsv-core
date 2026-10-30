'use strict'

/**
 * Read a SECURITY option from a caller's options object, counting only what the caller put on
 * that object itself.
 *
 * Plain `opts.requirePow` also finds a value inherited through the prototype chain, so
 * `Object.prototype.requirePow = false` — prototype pollution anywhere else in the process —
 * turned off proof-of-work checking for every caller that passed `{}` or no options at all.
 * Measured on 1.11.0: a header whose work fails and whose merkle root matches came back
 * `valid: true`. The same holds for any option that relaxes a check or widens trust.
 *
 * A protected option that is visible on the object but NOT owned throws instead of reading as
 * absent. Silently reading it as absent would drop a TIGHTENING option (minWork, minDifficulty)
 * from a caller who built their options with Object.create(defaults) or a class prototype, and
 * enforce nothing without saying so. Throwing is loud for that caller and for pollution alike,
 * and neither can fail open.
 *
 * An own property that is an accessor still counts (it is the caller's own object). Anything
 * that is not an object has no options, so the answer is undefined, which every call site
 * already treats as "not set".
 *
 * Ported from @smartledger/bsv's lib/util/own-option.js so the two libraries refuse the same
 * thing with the same words.
 */
function ownOption<T = unknown> (opts: unknown, key: string): T | undefined {
  if (opts === null || typeof opts !== 'object') return undefined
  const o = opts as Record<string, unknown>
  if (Object.prototype.hasOwnProperty.call(o, key)) return o[key] as T
  if (key in o) {
    throw new TypeError('option "' + key + '" is inherited from the prototype chain, not set on the ' +
      'options object itself, so it is refused: copy it onto the object you pass, e.g. ' +
      '{ ' + key + ': value }. (If you did not set it, something has polluted Object.prototype.)')
  }
  return undefined
}

export = ownOption
