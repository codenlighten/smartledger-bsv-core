/**
 * Shape of PublicKey, declared separately so modules inside the
 * address <-> publickey <-> privatekey cycle can refer to it as a TYPE without
 * adding a runtime import edge.
 *
 * This is the main reason the cyclic cluster is tractable: `import type` is
 * erased entirely, so type-level references across the cycle cost nothing at
 * runtime and cannot participate in a temporal-dead-zone hazard.
 */
import type BN = require('./crypto/bn')
import type { Point } from './crypto/point.types'

export interface PublicKey {
  readonly point: Point
  readonly compressed: boolean
  readonly network: unknown

  toDER: () => Buffer
  toBuffer: () => Buffer
  toString: () => string
  toHex: () => string
  toObject: () => { x: string, y: string, compressed: boolean }
  toAddress: (network?: unknown) => unknown
  inspect: () => string
  _getID: () => Buffer
  _classifyArgs: (data: unknown, extra: Record<string, unknown>) => PublicKeyInfo
}

export interface PublicKeyConstructor {
  new (data: unknown, extra?: unknown): PublicKey
  (data: unknown, extra?: unknown): PublicKey
  fromPrivateKey: (privkey: unknown) => PublicKey
  fromBuffer: (buf: Buffer, strict?: boolean) => PublicKey
  fromDER: (buf: Buffer, strict?: boolean) => PublicKey
  fromPoint: (point: Point, compressed?: boolean) => PublicKey
  fromString: (str: string) => PublicKey
  fromHex: (hex: string) => PublicKey
  fromX: (odd: boolean, x: BN) => PublicKey
  getValidationError: (data: unknown) => Error | undefined
  isValid: (data: unknown) => boolean

  // Internal transform helpers. Exposed on the constructor by the original
  // and reached from _classifyArgs, so they are part of the declared shape.
  _isPrivateKey: (param: unknown) => boolean
  _isBuffer: (param: unknown) => boolean
  _transformPrivateKey: (privkey: import('./privatekey.types').PrivateKey) => PublicKeyInfo
  _transformDER: (buf: Buffer, strict?: boolean) => PublicKeyInfo
  _transformX: (odd: boolean, x: BN) => PublicKeyInfo
  _transformObject: (json: { x: string, y: string, compressed?: boolean }) => PublicKeyInfo
}

/** The normalized form produced by the _transform* helpers. */
export interface PublicKeyInfo {
  point: Point
  compressed: boolean
  network?: unknown
}
