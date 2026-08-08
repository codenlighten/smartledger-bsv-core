/**
 * Shapes for ECDSA signing and verification.
 *
 * Separate module because ecdsa.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */
import type BN = require('./bn')
import type Signature = require('./signature')
import type { PublicKey } from '../publickey.types'
import type { PrivateKey } from '../privatekey.types'

export type Endian = 'big' | 'little'

export interface ECDSAObj {
  hashbuf?: Buffer | undefined
  endian?: Endian | undefined
  privkey?: PrivateKey | undefined
  pubkey?: PublicKey | undefined
  sig?: Signature | undefined
  k?: BN | undefined
  verified?: boolean | undefined
}

export interface ECDSA {
  hashbuf?: Buffer | undefined
  endian?: Endian | undefined
  privkey?: PrivateKey | undefined
  pubkey?: PublicKey | undefined
  sig?: Signature | undefined
  verified?: boolean | undefined

  /**
   * The ECDSA nonce.
   *
   * An accessor, not a data field, and deliberately so: a nonce may be
   * consumed by at most ONE signature — signing two messages under one k
   * reveals the private key. Assigning k marks it fresh; _findSignature marks
   * it stale once used and derives a new RFC 6979 nonce when it is stale.
   * _k / _kFresh are the backing fields for that state machine.
   */
  k?: BN | undefined
  _k?: BN | undefined
  _kFresh?: boolean | undefined

  set: (obj: ECDSAObj) => ECDSA
  privkey2pubkey: () => void
  calci: () => ECDSA
  randomK: () => ECDSA
  deterministicK: (badrs?: number) => ECDSA
  toPublicKey: () => PublicKey
  sigError: () => string | false
  /** The caller attaches `compressed` before handing the result to Signature. */
  _findSignature: (d: BN, e: BN) => { s: BN, r: BN, compressed?: boolean }
  sign: () => ECDSA
  signRandomK: () => ECDSA
  toString: () => string
  /**
   * Returns a BOOLEAN, not `this`.
   *
   * Changed in 7.0: it previously returned `this`, so `if (ecdsa.verify())`
   * was always truthy and silently accepted forged signatures. `verified` is
   * still set as a side effect; only the chained `.verify().verified` idiom
   * is gone.
   */
  verify: () => boolean
  verifyBool: () => boolean
}

export interface ECDSAConstructor {
  new (obj?: ECDSAObj): ECDSA
  (obj?: ECDSAObj): ECDSA
  fromString: (str: string) => ECDSA
  toLowS: (s: BN) => BN
  sign: (hashbuf: Buffer, privkey: PrivateKey, endian?: Endian) => Signature
  signWithCalcI: (hashbuf: Buffer, privkey: PrivateKey, endian?: Endian) => Signature
  signRandomK: (hashbuf: Buffer, privkey: PrivateKey, endian?: Endian) => Signature
  verify: (hashbuf: Buffer, sig: Signature, pubkey: PublicKey, endian?: Endian) => boolean
}
