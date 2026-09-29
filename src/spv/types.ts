/** Shapes for the SPV helpers. */
import type { BlockHeader } from '../block/types'
import type BN = require('../crypto/bn')

/** A proof-of-work limit or work floor: compact bits, hex, or a BN target/amount. */
export type WorkBound = number | string | BN

/** A header in any of the forms these helpers accept. */
export type HeaderLike = BlockHeader | Buffer | string

export interface MerkleProof {
  /** Display-order txid hex (64 chars). */
  txid: string
  /** 0-based position of the tx within the block. */
  index: number
  /** Sibling hashes, leaf -> root, display hex. '*' means "duplicate". */
  nodes?: string[]
  /** Display-order merkle root hex. */
  merkleRoot: string
}

export interface TxInclusionParams {
  txid: string
  index: number
  nodes?: string[]
  header: HeaderLike
  requirePow?: boolean
  /** Easiest target a header may declare, as compact bits, hex, or a BN target. */
  powLimit?: WorkBound
  /** Minimum work the header must represent, in HASHES. Difficulty 1 is about 4.295e9. */
  minWork?: WorkBound
  /**
   * The same floor in DIFFICULTY, the unit difficulty is quoted in: a real BSV header is
   * about 2.6e10. Exactly one of this and minWork; both throws.
   */
  minDifficulty?: number | string
}

export interface TxInclusionResult {
  /** rootMatches AND (proof-of-work valid, unless requirePow is false). */
  valid: boolean
  rootMatches: boolean
  /** The header meets the target it declares for itself. */
  powValid: boolean
  /** That declared target is no easier than powLimit. True when not checked. */
  targetAllowed: boolean
  /** The work it represents is at least minWork. True when not checked. */
  workSufficient: boolean
  /** Work the header represents, as a decimal string. */
  work: string
  /** The merkle root recomputed from the branch, display-order hex. */
  merkleRoot: string
  /** Display-order hash of the header the proof was checked against. */
  blockHash: string
}

export interface HeaderChainOpts {
  requirePow?: boolean
  /** Easiest target each header may declare, as compact bits. Default 0x1d00ffff. */
  powLimit?: WorkBound
  trustedHash?: string
}

/**
 * NOTE: the failure paths return a partial result — `anchorHash`, `tipHash`
 * and `work` are only present once the chain has been walked far enough to
 * know them. The optionality here reflects what the function actually returns
 * rather than an idealized shape; callers must not assume they are present
 * when `valid` is false. Normalizing this is an API decision, not a
 * conversion one.
 */
export interface HeaderChainResult {
  valid: boolean
  reason?: string
  count: number
  anchorHash?: string
  tipHash?: string
  work?: number
}
