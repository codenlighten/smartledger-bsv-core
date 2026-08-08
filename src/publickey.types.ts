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
}
