'use strict'

import BN = require('./bn')
import { secp256k1 } from '@noble/curves/secp256k1.js'
import type { Point, PointConstructor, CoordLike, NoblePoint } from './point.types'

// secp256k1 point + curve order from the audited @noble/curves implementation.
// This module preserves the (elliptic-derived) Point API the rest of the
// codebase depends on — mul/add/mulAdd/getX/getY/.x/.y/eq/isInfinity/validate,
// the static getG/getN/fromX/fromBuffer helpers — so ECDSA and key handling are
// unchanged. Only the underlying EC math moved from `elliptic` to `@noble`.
const NoblePoint = secp256k1.Point
const N_BIG = NoblePoint.Fn.ORDER

function bnToBig (bn: BN): bigint {
  // Coordinates and scalars in this codebase are always non-negative.
  return BigInt('0x' + (bn.toString(16) || '0'))
}

function bigToBN (big: bigint): BN {
  let h = big.toString(16)
  if (h.length % 2 !== 0) h = '0' + h
  return new BN(h, 16)
}

function toBig (v: CoordLike): bigint {
  if (v == null) throw new Error('Invalid Point')
  if (typeof v === 'bigint') return v
  if (typeof v === 'number') return BigInt(v)
  if (typeof v === 'string') return BigInt(v.indexOf('0x') === 0 ? v : '0x' + v)
  if (typeof v.toString === 'function') return bnToBig(v) // BN
  throw new Error('Invalid Point')
}

// Wrap a raw @noble point as a Point instance without re-validating (used by
// internal results of mul/add/getG/fromX which are already valid).
function wrap (noblePoint: NoblePoint): Point {
  const p = Object.create(Point.prototype) as Point
  p._p = noblePoint
  return p
}

// Derive the on-curve @noble point at the given X with the requested Y parity.
// Throws if X is not a valid curve x-coordinate. Low-level (no Point.validate),
// so it is safe to call from validate() without recursion.
function nobleFromX (odd: boolean, x: CoordLike): NoblePoint {
  // Build the compressed encoding via hex string padding (not BN.toBuffer) so we
  // don't perturb BN.toBuffer call counts the rest of the codebase may rely on.
  const xhex = toBig(x).toString(16).padStart(64, '0')
  return NoblePoint.fromHex((odd ? '03' : '02') + xhex)
}

// Check that (xb, yb) — raw bigint coordinates — lie on the curve, producing
// the same error messages the previous (elliptic) implementation did. Operates
// on raw coordinates so it works even for inputs @noble's fromAffine rejects
// outright (e.g. y = 0).
function checkOnCurve (xb: bigint, yb: bigint): void {
  let p2
  try {
    p2 = nobleFromX((yb & 1n) === 1n, xb)
  } catch (e) {
    throw new Error('Point does not lie on the curve')
  }
  if (p2.toAffine().y !== yb) {
    throw new Error('Invalid y value for curve.')
  }
}

/**
 * Instantiate a valid secp256k1 Point from the X and Y coordinates.
 * @param {BN|String} x - The X coordinate
 * @param {BN|String} y - The Y coordinate
 * @returns {Point}
 * @constructor
 */
const Point = function Point (this: Point, x: CoordLike, y: CoordLike, isRed?: boolean) {
  if (!(this instanceof Point)) {
    return new (Point as PointConstructor)(x, y, isRed)
  }
  let xb: bigint
  let yb: bigint
  try {
    xb = toBig(x)
    yb = toBig(y)
  } catch (e) {
    throw new Error('Invalid Point')
  }
  // Validate on the raw coordinates first (gives the specific curve/y errors and
  // works for coordinates @noble's fromAffine rejects, e.g. y = 0).
  checkOnCurve(xb, yb)
  try {
    this._p = NoblePoint.fromAffine({ x: xb, y: yb })
  } catch (e) {
    throw new Error('Invalid Point')
  }
  return this
} as unknown as PointConstructor

/**
 * Instantiate a valid secp256k1 Point from only the X coordinate.
 * @param {boolean} odd - If the Y coordinate is odd
 * @param {BN|String} x - The X coordinate
 * @returns {Point}
 */
Point.fromX = function fromX (odd: boolean, x: CoordLike): Point {
  // Declared outside the try: the original used `var`, which is
  // function-scoped, so `point` was visible below. `const` inside the block
  // would not be.
  let point: Point
  try {
    point = wrap(nobleFromX(odd, x))
  } catch (e) {
    throw new Error('Invalid X')
  }
  point.validate()
  return point
}

/**
 * @returns {Point} the secp256k1 base (generator) point.
 */
Point.getG = function getG (): Point {
  return wrap(NoblePoint.BASE)
}

/**
 * @returns {BN} the curve order n.
 */
Point.getN = function getN (): BN {
  return bigToBN(N_BIG)
}

/**
 * @returns {BN} the X coordinate of the Point.
 */
Point.prototype.getX = function getX (this: Point): BN {
  return bigToBN(this._p.toAffine().x)
}

/**
 * @returns {BN} the Y coordinate of the Point.
 */
Point.prototype.getY = function getY (this: Point): BN {
  return bigToBN(this._p.toAffine().y)
}

// `.x` / `.y` are accessed directly in a few places (e.g. ECDSA r = Q.x.umod(N)).
Object.defineProperty(Point.prototype, 'x', {
  configurable: true,
  enumerable: true,
  get: function () { return this.getX() }
})
Object.defineProperty(Point.prototype, 'y', {
  configurable: true,
  enumerable: true,
  get: function () { return this.getY() }
})

/**
 * Scalar multiply this point. Every valid secp256k1 point has order n
 * (cofactor 1), so k*P == (k mod n)*P; reducing mod n lets us always use
 * @noble's *constant-time* `multiply` (important for the secret signing nonce)
 * and naturally handles the boundary scalars used by validation / recovery
 * (e.g. n itself reduces to 0 -> the point at infinity).
 * @param {BN} k
 * @returns {Point}
 */
Point.prototype.mul = function mul (this: Point, k: BN | bigint | number): Point {
  const s = ((toBig(k) % N_BIG) + N_BIG) % N_BIG
  if (s === 0n || this._p.is0()) {
    return wrap(NoblePoint.ZERO)
  }
  return wrap(this._p.multiply(s))
}

/**
 * @param {Point} p
 * @returns {Point} this + p
 */
Point.prototype.add = function add (this: Point, p: Point): Point {
  return wrap(this._p.add(p._p))
}

/**
 * @returns {Point} k1*this + k2*p2 (used by ECDSA verification).
 */
Point.prototype.mulAdd = function mulAdd (this: Point, k1: BN | bigint | number, p2: Point, k2: BN | bigint | number): Point {
  return this.mul(k1).add(p2.mul(k2))
}

/**
 * @param {Point} p
 * @returns {boolean}
 */
Point.prototype.eq = function eq (this: Point, p: Point): boolean {
  return this._p.equals(p._p)
}

/**
 * @returns {boolean}
 */
Point.prototype.isInfinity = function isInfinity (this: Point): boolean {
  return this._p.is0()
}

/**
 * Will determine if the point is valid.
 * @returns {Point} this
 */
Point.prototype.validate = function validate (this: Point): Point {
  if (this.isInfinity()) {
    throw new Error('Point cannot be equal to Infinity')
  }
  const a = this._p.toAffine()
  checkOnCurve(a.x, a.y)
  // secp256k1 has cofactor 1, so on-curve implies order n; the old explicit
  // n*P == infinity check is therefore redundant.
  return this
}

/**
 * A "compressed" format point: the X coordinate plus a parity byte.
 * @param {Point} point
 * @returns {Buffer}
 */
Point.pointToCompressed = function pointToCompressed (point: Point): Buffer {
  const xbuf = point.getX().toBuffer({ size: 32 })
  const ybuf = point.getY().toBuffer({ size: 32 })

  let prefix: Buffer
  // ybuf is a fixed 32-byte buffer from toBuffer({ size: 32 }), so the last
  // byte is always present.
  const odd = (ybuf[ybuf.length - 1] as number) % 2
  if (odd !== 0) {
    prefix = Buffer.from([0x03])
  } else {
    prefix = Buffer.from([0x02])
  }
  return Buffer.concat([prefix, xbuf])
}

/**
 * @param {Buffer} buf A compressed point.
 * @returns {Point}
 */
Point.pointFromCompressed = function (buf: Buffer): Point {
  if (buf.length !== 33) {
    throw new Error('invalid buffer length')
  }
  const prefix = buf[0]
  let odd
  if (prefix === 0x03) {
    odd = true
  } else if (prefix === 0x02) {
    odd = false
  } else {
    throw new Error('invalid value of compressed prefix')
  }

  const x = BN.fromBuffer(buf.slice(1, 33))
  return Point.fromX(odd, x)
}

/**
 * @returns {Buffer} this point as a compressed buffer.
 */
Point.prototype.toBuffer = function (this: Point): Buffer {
  return Point.pointToCompressed(this)
}

/**
 * @returns {string} this point as a compressed hex string.
 */
Point.prototype.toHex = function (this: Point): string {
  return this.toBuffer().toString('hex')
}

Point.fromBuffer = function (buf: Buffer): Point {
  return Point.pointFromCompressed(buf)
}

Point.fromHex = function (hex: string): Point {
  return Point.fromBuffer(Buffer.from(hex, 'hex'))
}

export = Point
