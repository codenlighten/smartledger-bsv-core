/**
 * Shape of HDPrivateKey, declared separately so hdpublickey — which is on the
 * other side of the cycle — can refer to it as a TYPE without adding a runtime
 * import edge back.
 *
 * Instance fields are `readonly` because they genuinely are: every one is
 * installed through `JSUtil.defineImmutable`, which uses a non-writable,
 * non-configurable property descriptor. Reassigning one throws in strict mode.
 * That is the opposite of the interpreter limits, which look like constants
 * and are not; here the readonly modifier tells the truth.
 */
import type BN = require('./crypto/bn')
import type { PrivateKey } from './privatekey.types'
import type { PublicKey } from './publickey.types'
import type { HDPublicKey } from './hdpublickey.types'

import type { Network } from './networks.types'

/** A network, or the name/version-byte that Networks.get() resolves to one. */
export type NetworkLike = Network | string | number

/** The per-field buffer view a serialized key is decomposed into. */
export interface HDBuffers {
  version: Buffer
  depth: Buffer
  parentFingerPrint: Buffer
  childIndex: Buffer
  chainCode: Buffer
  privateKey: Buffer
  checksum?: Buffer | undefined
  xprivkey?: Buffer | string | undefined
}

export interface HDPrivateKey {
  readonly _buffers: HDBuffers
  readonly xprivkey: string
  readonly network: { xprivkey: number, name: string }
  readonly depth: number
  readonly privateKey: PrivateKey
  readonly publicKey: PublicKey
  readonly fingerPrint: Buffer

  /** Memoized by _calcHDPublicKey; derivation is not free. */
  _hdPublicKey?: HDPublicKey | null | undefined
  readonly hdPublicKey: HDPublicKey
  readonly xpubkey: string

  derive: (arg: string | number, hardened?: boolean) => HDPrivateKey
  deriveChild: (arg: string | number, hardened?: boolean) => HDPrivateKey
  deriveNonCompliantChild: (arg: string | number, hardened?: boolean) => HDPrivateKey
  _deriveWithNumber: (index: number, hardened?: boolean | null, nonCompliant?: boolean) => HDPrivateKey
  _deriveFromString: (path: string, nonCompliant?: boolean) => HDPrivateKey

  _buildFromJSON: (arg: any) => HDPrivateKey
  _buildFromObject: (arg: any) => HDPrivateKey
  _buildFromSerialized: (arg: string) => HDPrivateKey
  _buildFromBuffers: (arg: HDBuffers) => HDPrivateKey
  _generateRandomly: (network?: NetworkLike) => HDPrivateKey
  _calcHDPublicKey: () => void

  toString: () => string
  inspect: () => string
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  toBuffer: () => Buffer
  toHex: () => string
}

/**
 * Offsets and sizes are enumerated rather than reached through an index
 * signature. They are byte positions into a serialized key: an index signature
 * would type them `unknown` and force a cast at every slice, which is exactly
 * where an off-by-one silently produces a valid-looking key for the wrong
 * seed.
 */
export interface HDPrivateKeyConstructor {
  (arg?: unknown): HDPrivateKey
  new (arg?: unknown): HDPrivateKey
  prototype: HDPrivateKey

  fromRandom: (network?: NetworkLike) => HDPrivateKey
  fromString: (arg: string) => HDPrivateKey
  fromObject: (arg: any) => HDPrivateKey
  fromSeed: (hexa: string | Buffer, network?: NetworkLike) => HDPrivateKey
  fromBuffer: (buf: Buffer) => HDPrivateKey
  fromHex: (hex: string) => HDPrivateKey

  /** `hardened` is passed as null by the derivation helpers, meaning
   *  "not specified" rather than "not hardened". */
  isValidPath: (arg: string | number, hardened?: boolean | null) => boolean
  isValidSerialized: (data: string | Buffer, network?: NetworkLike) => boolean
  getSerializedError: (data: string | Buffer, network?: NetworkLike) => Error | null
  _getDerivationIndexes: (path: string) => number[] | null
  _validateNetwork: (data: Buffer, networkArg?: NetworkLike) => Error | null
  _validateBufferArguments: (arg: HDBuffers) => void

  DefaultDepth: number
  DefaultFingerprint: number
  DefaultChildIndex: number
  Hardened: number
  MaxIndex: number
  RootElementAlias: string[]

  VersionSize: number
  DepthSize: number
  ParentFingerPrintSize: number
  ChildIndexSize: number
  ChainCodeSize: number
  PrivateKeySize: number
  CheckSumSize: number
  DataLength: number
  SerializedByteSize: number

  VersionStart: number
  VersionEnd: number
  DepthStart: number
  DepthEnd: number
  ParentFingerPrintStart: number
  ParentFingerPrintEnd: number
  ChildIndexStart: number
  ChildIndexEnd: number
  ChainCodeStart: number
  ChainCodeEnd: number
  PrivateKeyStart: number
  PrivateKeyEnd: number
  ChecksumStart: number
  ChecksumEnd: number
}

export type { BN }
