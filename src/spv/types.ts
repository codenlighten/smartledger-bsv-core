/** Shapes for the SPV helpers. */
import type { BlockHeader } from '../block/types'

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
}

export interface TxInclusionResult {
  /** rootMatches AND (proof-of-work valid, unless requirePow is false). */
  valid: boolean
  rootMatches: boolean
  powValid: boolean
  /** The merkle root recomputed from the branch, display-order hex. */
  merkleRoot: string
  /** Display-order hash of the header the proof was checked against. */
  blockHash: string
}

export interface HeaderChainOpts {
  requirePow?: boolean
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
