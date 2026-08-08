/**
 * Shapes for ECDSA signatures.
 *
 * Separate module because signature.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */
import type BN = require('bn.js')

/** The parsed components of a DER-encoded signature. */
export interface ParsedDER {
  header: number
  length: number
  rheader: number
  rlength: number
  rneg: boolean
  rbuf: Buffer
  r: BN
  sheader: number
  slength: number
  sneg: boolean
  sbuf: Buffer
  s: BN
}

export interface SignatureObj {
  r?: BN | undefined
  s?: BN | undefined
  /** Public-key recovery parameter, 0..3. */
  i?: number | undefined
  /** Whether the recovered pubkey is compressed. */
  compressed?: boolean | undefined
  nhashtype?: number | undefined
}

export interface Signature {
  r: BN
  s: BN
  i?: number | undefined
  compressed?: boolean | undefined
  nhashtype?: number | undefined

  set: (obj: SignatureObj) => Signature
  toCompact: (i?: number, compressed?: boolean) => Buffer
  toBuffer: () => Buffer
  toDER: () => Buffer
  toString: () => string
  toTxFormat: () => Buffer
  hasLowS: () => boolean
  hasDefinedHashtype: () => boolean
  isCanonical: () => boolean
  toCanonical: () => Signature
  /** Throws on an invalid signature; returns true otherwise (NOT `this`). */
  validate: () => boolean
  isValid: () => boolean
  /**
   * Asserts r and s are in (0, n) and s is low-S. Throws if not.
   * Deliberately does NOT rewrite a high-S signature: ECDSA accepts s and n-s
   * equally, so normalizing would verify identically and merely hide from the
   * caller that they were handed a malleated signature.
   */
  applySecurityPatches: () => Signature
}

export interface SignatureConstructor {
  new (r?: BN | SignatureObj, s?: BN): Signature
  (r?: BN | SignatureObj, s?: BN): Signature
  fromCompact: (buf: Buffer) => Signature
  fromDER: (buf: Buffer, strict?: boolean) => Signature
  fromBuffer: (buf: Buffer, strict?: boolean) => Signature
  fromTxFormat: (buf: Buffer) => Signature
  fromString: (str: string) => Signature
  parseDER: (buf: Buffer, strict?: boolean) => ParsedDER
  /** Strict DER + hashtype check used for transaction signatures. */
  isTxDER: (buf: Buffer) => boolean
  SIGHASH_ALL: number
  SIGHASH_NONE: number
  SIGHASH_SINGLE: number
  SIGHASH_FORKID: number
  SIGHASH_ANYONECANPAY: number
}
