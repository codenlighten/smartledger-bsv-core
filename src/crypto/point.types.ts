/**
 * Shapes for the secp256k1 Point wrapper.
 *
 * Separate module because point.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */
import type BN = require('bn.js')
import { secp256k1 } from '@noble/curves/secp256k1.js'

/**
 * The underlying @noble curve point.
 *
 * Derived from the library rather than restated, so it tracks @noble's own
 * type across upgrades instead of drifting from it.
 */
export type NoblePoint = ReturnType<typeof secp256k1.Point.fromHex>

/** Anything the coordinate coercion (`toBig`) accepts. */
export type CoordLike = BN | bigint | number | string

export interface Point {
  /**
   * The wrapped @noble point. Internal — this class exists to hide it — but
   * typed properly rather than as `unknown`, so the wrapper's own arithmetic
   * is checked instead of casting at every call site.
   */
  _p: NoblePoint

  getX: () => BN
  getY: () => BN
  mul: (k: BN | bigint | number) => Point
  add: (p: Point) => Point
  mulAdd: (k1: BN | bigint | number, p2: Point, k2: BN | bigint | number) => Point
  eq: (p: Point) => boolean
  isInfinity: () => boolean
  validate: () => Point
  toBuffer: () => Buffer
  toHex: () => string
}

export interface PointConstructor {
  new (x: CoordLike, y: CoordLike, isRed?: boolean): Point
  (x: CoordLike, y: CoordLike, isRed?: boolean): Point
  fromX: (odd: boolean, x: CoordLike) => Point
  getG: () => Point
  getN: () => BN
  pointToCompressed: (point: Point) => Buffer
  pointFromCompressed: (buf: Buffer) => Point
  fromBuffer: (buf: Buffer) => Point
  fromHex: (hex: string) => Point
}
