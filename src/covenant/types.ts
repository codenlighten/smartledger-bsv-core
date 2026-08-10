/**
 * Shapes for the covenant primitives — OP_PUSH_TX and the BIP-143 preimage
 * helpers built on it.
 *
 * These live in core rather than in the smart-contract package because they
 * have two independent consumers: the contract tooling, and ordinals' OrdLock
 * covenants.
 */
import type { Script } from '../script/script.types'
import type { Transaction, Output, Input } from '../transaction/types'
import type { PrivateKey } from '../privatekey.types'
import type { PublicKey } from '../publickey.types'
import type { Address } from '../address.types'
import type BN = require('../crypto/bn')

/** A payment destination the P2PKH helper accepts. */
export type PayeeLike = Address | PublicKey | string

/** Options for `verify()` — how to run the interpreter over a script pair. */
export interface VerifyOptions {
  /** Interpreter flags. Defaults to the covenant flag set. */
  flags?: number | undefined
  /** The spending transaction the unlocking script belongs to. */
  tx?: Transaction | undefined
  inputIndex?: number | undefined
  /** Input value, required for a correct BIP-143 preimage. */
  satoshis?: number | undefined
}

/** Options for `fundAndSpend()` — build a funding/spending transaction pair. */
export interface FundAndSpendOptions {
  /** Extra outputs appended to the spending transaction, in order. */
  outputs?: Output[] | undefined
}

/**
 * Options for `PushTx.grind()`.
 *
 * A bare number is also accepted and treated as `maxTries`, which is why the
 * grind parameter is a union rather than this interface alone.
 */
export interface GrindOptions {
  /** Attempts before giving up. Default 5000. */
  maxTries?: number | undefined
  /** First nonce to try. Default 0. */
  start?: number | undefined
  /**
   * Which field carries the grind nonce. Use 'sequence' when the covenant
   * pins nLockTime for a real CLTV timelock — the input's sequence is swept
   * down from 0xfffffffe instead, keeping it non-final so CLTV still fires.
   * Not for CSV covenants, which encode meaning in the sequence itself.
   */
  field?: 'nLockTime' | 'sequence' | undefined
  sighashType?: number | undefined
}

/** What `grind()` returns once it finds a satisfying nonce. */
export interface GrindResult {
  preimage: Buffer
  tries: number
  field: 'nLockTime' | 'sequence'
  nonce: number
}

/** What `verify()` reports. */
export interface VerifyResult {
  ok: boolean
  err: string
}

/** What `fundAndSpend()` returns. */
export interface FundAndSpendResult {
  funding: Transaction
  spend: Transaction
}

/** Options for the OP_PUSH_TX core builder. */
export interface PushTxOptions {
  /** Override the sighash type the covenant commits to. */
  sighashType?: number | undefined
  /** Element size the preimage is split at. */
  size?: number | undefined
}

export type { Script, Transaction, Output, Input, PrivateKey, PublicKey, Address, BN }
