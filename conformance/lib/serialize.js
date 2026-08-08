'use strict'

// Canonical, diff-friendly serialization for conformance fixtures.
//
// Values are encoded as tagged strings rather than nested objects so that a
// regression shows up as a readable one-line diff:
//
//   - "buf:76a914...88ac"
//   + "buf:76a914...87"
//
// rather than a restructured object tree.

/** Encode a Buffer/Uint8Array as `buf:<hex>`. */
function encodeBytes (v) {
  return 'buf:' + Buffer.from(v).toString('hex')
}

/** Duck-type a bn.js instance without importing the library under test. */
function isBN (v) {
  return v !== null && typeof v === 'object' &&
    typeof v.toString === 'function' &&
    typeof v.iadd === 'function' &&
    typeof v.umod === 'function'
}

/**
 * Convert an arbitrary value into a canonical JSON-safe form.
 *
 * Rules:
 *   Buffer/TypedArray -> "buf:<hex>"
 *   BN                -> "bn:<decimal>"
 *   BigInt            -> "big:<decimal>"
 *   undefined         -> "undefined"   (JSON drops bare undefined; we must not)
 *   -0                -> "-0"          (JSON renders -0 as 0)
 *   NaN/Infinity      -> "num:NaN" etc (JSON renders these as null)
 *   function          -> "fn:<name>"   (identity is not comparable; arity is)
 *   Map/Set           -> ordered arrays
 *   plain object      -> key-sorted object
 *
 * Objects exposing toObject()/toJSON() are NOT auto-unwrapped: which of the two
 * a class implements is itself part of the API surface, so suites call the one
 * they mean explicitly.
 */
function normalize (v, seen) {
  seen = seen || new Set()

  if (v === undefined) return 'undefined'
  if (v === null) return null

  const t = typeof v

  if (t === 'bigint') return 'big:' + v.toString()
  if (t === 'symbol') return 'sym:' + String(v.description)
  if (t === 'function') return 'fn:' + (v.name || '<anon>') + '/' + v.length

  if (t === 'number') {
    if (Number.isNaN(v)) return 'num:NaN'
    if (v === Infinity) return 'num:Infinity'
    if (v === -Infinity) return 'num:-Infinity'
    if (Object.is(v, -0)) return '-0'
    return v
  }

  if (t === 'string' || t === 'boolean') return v

  // Reference types past this point.
  if (seen.has(v)) return '<circular>'

  if (Buffer.isBuffer(v) || ArrayBuffer.isView(v)) return encodeBytes(v)
  if (v instanceof ArrayBuffer) return encodeBytes(new Uint8Array(v))
  if (v instanceof Date) return 'date:' + v.toISOString()
  if (v instanceof RegExp) return 'regexp:' + v.toString()
  if (isBN(v)) return 'bn:' + v.toString(10)

  if (v instanceof Error) {
    return { __error: v.name, message: v.message }
  }

  seen.add(v)
  try {
    if (Array.isArray(v)) return v.map((x) => normalize(x, seen))
    if (v instanceof Map) {
      return { __map: [...v.entries()].map(([k, x]) => [normalize(k, seen), normalize(x, seen)]) }
    }
    if (v instanceof Set) {
      return { __set: [...v.values()].map((x) => normalize(x, seen)) }
    }

    const out = {}
    for (const k of Object.keys(v).sort()) out[k] = normalize(v[k], seen)
    return out
  } finally {
    seen.delete(v)
  }
}

/**
 * Run a case function and capture its outcome, success or failure alike.
 *
 * A thrown error is a recorded result, not a harness failure: "this input is
 * rejected" is behavior we are pinning down just as firmly as any return value.
 */
function capture (fn) {
  let value
  try {
    value = fn()
  } catch (err) {
    return {
      outcome: 'throws',
      error: {
        // `name` is the portable contract across a reimplementation;
        // `message` is recorded too but compared only in strict mode.
        name: (err && err.name) || 'Error',
        message: (err && err.message) || String(err)
      }
    }
  }
  return { outcome: 'ok', value: normalize(value) }
}

/**
 * Async form of capture(). Today's core API is synchronous, but the TypeScript
 * rewrite may make some operations async; the corpus must survive that without
 * every suite being rewritten.
 */
async function captureAsync (fn) {
  let value
  try {
    value = fn()
    if (value && typeof value.then === 'function') value = await value
  } catch (err) {
    return {
      outcome: 'throws',
      error: {
        name: (err && err.name) || 'Error',
        message: (err && err.message) || String(err)
      }
    }
  }
  return { outcome: 'ok', value: normalize(value) }
}

/** Stable JSON: keys already sorted by normalize(), fixed 2-space indent. */
function stringify (obj) {
  return JSON.stringify(obj, null, 2) + '\n'
}

module.exports = { normalize, capture, captureAsync, stringify, isBN }
