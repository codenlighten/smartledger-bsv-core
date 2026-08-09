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

  _buildFromPrivate: (arg: unknown) => HDPublicKey
  _buildFromObject: (arg: any) => HDPublicKey
  _buildFromSerialized: (arg: string | Buffer) => HDPublicKey
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

  fromHDPrivateKey: (hdPrivateKey: unknown) => HDPublicKey
  fromString: (arg: string) => HDPublicKey
  fromObject: (arg: any) => HDPublicKey
  fromBuffer: (arg: Buffer) => HDPublicKey
  fromHex: (hex: string) => HDPublicKey

  isValidPath: (arg: string | number) => boolean
  isValidSerialized: (data: string | Buffer, network?: unknown) => boolean
  getSerializedError: (data: string | Buffer, network?: unknown) => Error | null
  _validateNetwork: (data: unknown, networkArg?: unknown) => Error | null
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
