/**
 * Shape of HDPublicKey. Separated from the implementation for the same reason
 * as its private counterpart: hdprivatekey needs the type, not the module.
 *
 * The two are near-mirrors, but the differences are load-bearing and are not
 * factored into a shared base: a public key has no `privateKey`, its buffers
 * carry `publicKey` where the other carries `privateKey`, and its derivation
 * REJECTS hardened indexes rather than accepting them. A shared base would
 * have to make all three optional, which would type away the one distinction
 * that matters at a call site.
 */
import type { PublicKey } from './publickey.types'

import type { Network } from './networks.types'

/** A network, or the name/version-byte that Networks.get() resolves to one. */
export type NetworkLike = Network | string | number

/**
 * What _buildFromPrivate accepts: an HDPrivateKey, seen structurally so this
 * module does not take a type dependency on the other side of the cycle.
 */
export interface HDPrivateKeyLike {
  _buffers: { version: Buffer, depth: Buffer, parentFingerPrint: Buffer, childIndex: Buffer, chainCode: Buffer, privateKey: Buffer, checksum?: Buffer | undefined }
  privateKey: { publicKey: { toBuffer: () => Buffer } }
  network: { xpubkey: number }
}

/** The per-field buffer view a serialized key is decomposed into. */
export interface HDPublicBuffers {
  version: Buffer
  depth: Buffer
  parentFingerPrint: Buffer
  childIndex: Buffer
  chainCode: Buffer
  publicKey: Buffer
  checksum?: Buffer | undefined
  xpubkey?: Buffer | string | undefined
}

/**
 * The transitional shape inside _buildFromPrivate: a clone of the PRIVATE
 * key's buffers, being rewritten field by field into the public ones. It is
 * neither shape while that is happening — privateKey and xprivkey are cleared
 * to undefined rather than deleted — so it gets its own name instead of a cast
 * that would claim the object is already an HDPublicBuffers.
 */
export type HDPrivateToPublicBuffers =
  Omit<HDPublicBuffers, 'publicKey'> & {
    publicKey?: Buffer
    privateKey?: Buffer | undefined
    xprivkey?: unknown
  }

/**
 * The plain-object form the constructor and fromObject() accept. Fields arrive
 * in whichever representation the producer used — a network name or a version
 * buffer, a number or a buffer for depth — and _buildFromObject normalizes
 * each. That is why they are unions rather than one settled shape.
 */
export interface HDPublicKeyObj {
  network?: NetworkLike | undefined
  version?: Buffer | undefined
  depth?: number | Buffer | undefined
  parentFingerPrint?: number | Buffer | undefined
  childIndex?: number | Buffer | undefined
  chainCode?: string | Buffer | undefined
  publicKey?: string | Buffer | undefined
  checksum?: number | Buffer | undefined
  [key: string]: unknown
}

export interface HDPublicKey {
  readonly _buffers: HDPublicBuffers
  readonly xpubkey: string
  readonly network: { xpubkey: number, name: string }
  readonly depth: number
  readonly publicKey: PublicKey
  readonly fingerPrint: Buffer

  derive: (arg: string | number, hardened?: boolean) => HDPublicKey
  deriveChild: (arg: string | number, hardened?: boolean) => HDPublicKey
  _deriveWithNumber: (index: number, hardened?: boolean) => HDPublicKey
  _deriveFromString: (path: string) => HDPublicKey

  _buildFromPrivate: (arg: HDPrivateKeyLike) => HDPublicKey
  _buildFromObject: (arg: HDPublicKeyObj) => HDPublicKey
  _buildFromSerialized: (arg: string) => HDPublicKey
  _buildFromBuffers: (arg: HDPublicBuffers) => HDPublicKey

  toString: () => string
  inspect: () => string
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  toBuffer: () => Buffer
  toHex: () => string
}

/** Offsets enumerated for the same reason as HDPrivateKeyConstructor's. */
export interface HDPublicKeyConstructor {
  (arg?: unknown): HDPublicKey
  new (arg?: unknown): HDPublicKey
  prototype: HDPublicKey

  fromHDPrivateKey: (hdPrivateKey: HDPrivateKeyLike) => HDPublicKey
  fromString: (arg: string) => HDPublicKey
  fromObject: (arg: HDPublicKeyObj) => HDPublicKey
  fromBuffer: (arg: Buffer) => HDPublicKey
  fromHex: (hex: string) => HDPublicKey

  isValidPath: (arg: string | number) => boolean
  isValidSerialized: (data: string | Buffer, network?: NetworkLike) => boolean
  getSerializedError: (data: string | Buffer, network?: NetworkLike) => Error | null
  _validateNetwork: (data: Buffer, networkArg?: NetworkLike) => Error | null
  _validateBufferArguments: (arg: HDPublicBuffers) => void

  Hardened: number
  RootElementAlias: string[]

  VersionSize: number
  DepthSize: number
  ParentFingerPrintSize: number
  ChildIndexSize: number
  ChainCodeSize: number
  PublicKeySize: number
  CheckSumSize: number
  DataSize: number
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
  PublicKeyStart: number
  PublicKeyEnd: number
  ChecksumStart: number
  ChecksumEnd: number
}
