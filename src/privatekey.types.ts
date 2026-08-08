/**
 * Shape of PrivateKey, declared separately so modules inside the
 * address <-> publickey <-> privatekey cycle can refer to it as a TYPE
 * without adding a runtime import edge.
 */
import type BN = require('./crypto/bn')
import type { PublicKey } from './publickey.types'

/** The normalized form produced by the _transform* helpers. */
export interface PrivateKeyInfo {
  bn?: BN
  compressed?: boolean
  network?: unknown
}

export interface PrivateKey {
  readonly bn: BN
  readonly compressed: boolean
  readonly network: { privatekey: number, toString: () => string }
  /** Accessor backed by toPublicKey(), bound in the constructor. */
  readonly publicKey: PublicKey
  /** Memoized result of toPublicKey(); derivation is not free. */
  _pubkey?: PublicKey

  _classifyArguments: (data: unknown, network?: unknown) => PrivateKeyInfo
  toString: () => string
  toWIF: () => string
  toBigNumber: () => BN
  toBuffer: () => Buffer
  toHex: () => string
  toPublicKey: () => PublicKey
  toAddress: (network?: unknown) => unknown
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  inspect: () => string
}

export interface PrivateKeyConstructor {
  new (data?: unknown, network?: unknown): PrivateKey
  (data?: unknown, network?: unknown): PrivateKey
  fromBuffer: (buf: Buffer, network?: unknown, compressed?: boolean) => PrivateKey
  fromHex: (hex: string, network?: unknown, compressed?: boolean) => PrivateKey
  fromString: (str: string, network?: unknown) => PrivateKey
  fromWIF: (str: string, network?: unknown) => PrivateKey
  fromObject: (obj: Record<string, unknown>) => PrivateKey
  fromJSON: (obj: Record<string, unknown>) => PrivateKey
  fromRandom: (network?: unknown) => PrivateKey
  getValidationError: (data: unknown, network?: unknown) => Error | undefined
  isValid: (data: unknown, network?: unknown) => boolean

  _getRandomBN: () => BN
  _transformBuffer: (buf: Buffer, network?: unknown) => PrivateKeyInfo
  _transformBNBuffer: (buf: Buffer, network?: unknown, compressed?: boolean) => PrivateKeyInfo
  _transformWIF: (str: string, network?: unknown) => PrivateKeyInfo
  _transformObject: (json: Record<string, unknown>) => PrivateKeyInfo
}
