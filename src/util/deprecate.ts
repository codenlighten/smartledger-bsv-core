'use strict'

/**
 * Runtime deprecation notices.
 *
 * A semver major is a promise that the consumer's code breaks. The fix is not to keep
 * bad APIs; it is to separate the moment we say "this is wrong" from the moment we
 * break callers:
 *
 *   minor    mark it. Callers see a warning naming the replacement, and keep working.
 *            `removeIn` states the version that will break them.
 *   major    remove it, on a schedule announced at least one minor in advance.
 *
 * Deprecating is therefore a NON-breaking act and belongs in a minor. That is what
 * makes a long-lived 1.x possible: correctness fixes ship continuously, breakage
 * batches into one planned major with a migration path already in the consumer's logs.
 *
 * Nothing here ever throws on the consumer's path. A deprecation that throws is just a
 * breaking change wearing a warning's name.
 *
 * Ported from @smartledger/bsv's lib/util/deprecate.js (9.1.0) so the two libraries
 * mark the same APIs with the same wording and the same env switch.
 */

import type { DeprecationOptions, FiredNotice } from './deprecate.types'

let seen: Record<string, boolean> = Object.create(null)

/** Every notice fired this process, for tests and for `--audit`-style tooling. */
const fired: FiredNotice[] = []

/**
 * Warnings are on unless explicitly silenced. Consumers who have logged the migration
 * and do not want the noise set BSV_NO_DEPRECATION_WARNINGS=1; the record in `fired` is
 * kept either way so tooling still sees it.
 *
 * Guarded like every other process.env read in src/: this module is inlined into every
 * bundle, so an unguarded read is a ReferenceError in any browser bundler that does not
 * shim `process`.
 */
let enabled = !(typeof process !== 'undefined' && process.env &&
  process.env.BSV_NO_DEPRECATION_WARNINGS === '1')

/**
 * Validate HERE, at the author's one-time wrapping call, not inside the returned
 * wrapper. Deferring it meant `deprecate.fn(f)` wrapped cleanly and then threw on every
 * subsequent call — turning a deprecation into the breaking change this module exists to
 * avoid, at a call site far from the mistake.
 */
function assertOpts (opts: DeprecationOptions | undefined, caller: string): void {
  if (!opts || typeof opts.what !== 'string' || opts.what === '') {
    throw new TypeError(caller + '() requires { what: string }')
  }
}

function format (opts: DeprecationOptions): string {
  let msg = '[@smartledger/bsv-core] ' + opts.what + ' is deprecated'
  if (opts.since) msg += ' since ' + opts.since
  msg += '.'
  if (opts.why) msg += ' ' + opts.why.charAt(0).toUpperCase() + opts.why.slice(1) + '.'
  if (opts.use) msg += ' Use ' + opts.use + ' instead.'
  msg += opts.removeIn
    ? ' It will be removed in ' + opts.removeIn + '.'
    : ' A removal version has not been set; it will not be removed in a 1.x release.'
  return msg
}

/**
 * Emit a deprecation notice at most once per `what` per process.
 *
 * @returns true if this call emitted (false if already seen)
 */
function deprecate (opts: DeprecationOptions): boolean {
  if (!opts || !opts.what) throw new TypeError('deprecate() requires { what }')
  if (seen[opts.what]) return false
  seen[opts.what] = true

  const message = format(opts)
  fired.push({
    what: opts.what,
    since: opts.since ?? null,
    removeIn: opts.removeIn ?? null,
    use: opts.use ?? null,
    message
  })
  if (enabled) console.warn(message)
  return true
}

/**
 * Wrap a function so calling it warns once, then behaves exactly as before. Preserves
 * name, arity and `this`, so it is safe on prototype methods.
 */
function fn<F extends (this: unknown, ...args: never[]) => unknown> (f: F, opts: DeprecationOptions): F {
  if (typeof f !== 'function') throw new TypeError('deprecate.fn() requires a function')
  assertOpts(opts, 'deprecate.fn')
  const wrapper = function (this: unknown, ...args: never[]): unknown {
    deprecate(opts)
    return f.apply(this, args)
  }
  Object.defineProperty(wrapper, 'name', { value: f.name, configurable: true })
  Object.defineProperty(wrapper, 'length', { value: f.length, configurable: true })
  ;(wrapper as unknown as { __wrapped: F }).__wrapped = f
  ;(wrapper as unknown as { __deprecation: DeprecationOptions }).__deprecation = opts
  return wrapper as unknown as F
}

/**
 * Deprecate a property access (an alias namespace, a renamed field). Warns on first
 * read; the value is computed once and cached.
 */
function property<T extends object> (target: T, name: string, get: () => unknown, opts: DeprecationOptions): T {
  assertOpts(opts, 'deprecate.property')
  let cached: unknown
  let loaded = false
  Object.defineProperty(target, name, {
    configurable: true,
    enumerable: true,
    get: function () {
      deprecate(opts)
      if (!loaded) { cached = get(); loaded = true }
      return cached
    }
  })
  return target
}

const api = deprecate as typeof deprecate & {
  fn: typeof fn
  property: typeof property
  /** Notices fired this process, in order. */
  fired: () => FiredNotice[]
  /** Silence output. The `fired` record is still kept. */
  setEnabled: (v: unknown) => void
  isEnabled: () => boolean
  /** Test hook: forget what has been warned about. */
  reset: () => void
}

api.fn = fn
api.property = property
api.fired = function (): FiredNotice[] { return fired.slice() }
api.setEnabled = function (v: unknown): void { enabled = !!v }
api.isEnabled = function (): boolean { return enabled }
api.reset = function (): void {
  seen = Object.create(null)
  fired.length = 0
}

export = api
