/**
 * Shapes for the block modules.
 *
 * Separate from the implementation because blockheader.ts uses `export =` to
 * keep its CommonJS `require()` shape, and TypeScript forbids an export
 * assignment alongside other exported members.
 */
import type BN = require('bn.js')
import type { BufferReader, BufferWriter } from '../encoding/types'

/**
 * The plain-object form ACCEPTED by the constructor and fromObject().
 *
 * prevHash/merkleRoot may be display-order hex strings or internal-order
 * Buffers; _fromObject normalizes them. toObject() emits the hex form, which
 * is why the input and normalized shapes are separate types rather than one
 * permissive interface — conflating them is how a display-order string ends up
 * being treated as internal-order bytes.
 */
export interface BlockHeaderObj {
  hash?: string | undefined
  version: number
  prevHash: Buffer | string
  merkleRoot: Buffer | string
  time: number
  timestamp?: number | undefined
  bits: number
  nonce: number
}

/** The normalized form produced by _from/_fromObject/_fromBufferReader. */
export interface BlockHeaderInfo {
  hash?: string | undefined
  version: number
  prevHash: Buffer
  merkleRoot: Buffer
  time: number
  timestamp?: number | undefined
  bits: number
  nonce: number
}

export interface BlockHeader {
  version: number
  prevHash: Buffer
  merkleRoot: Buffer
  time: number
  timestamp: number
  bits: number
  nonce: number

  /**
   * Big-endian (display order) hash, computed lazily and cached in `_id`.
   * `id` and `hash` are the same accessor — see blockheader.ts.
   */
  readonly id: string
  readonly hash: string
  _id?: string

  toObject: () => BlockHeaderObj
  toJSON: () => BlockHeaderObj
  toBuffer: () => Buffer
  toString: () => string
  toBufferWriter: (bw?: BufferWriter) => BufferWriter
  getTargetDifficulty: (bits?: number) => BN
  getDifficulty: () => number
  _getHash: () => Buffer
  validTimestamp: () => boolean
  validProofOfWork: () => boolean
  inspect: () => string
}

export interface BlockHeaderConstructor {
  new (arg?: BlockHeaderObj | Buffer | string): BlockHeader
  (arg?: BlockHeaderObj | Buffer | string): BlockHeader
  _from: (arg: BlockHeaderObj | Buffer | string) => BlockHeaderInfo
  _fromObject: (data: BlockHeaderObj) => BlockHeaderInfo
  fromObject: (obj: BlockHeaderObj) => BlockHeader
  fromRawBlock: (data: Buffer | string) => BlockHeader
  fromBuffer: (buf: Buffer) => BlockHeader
  fromString: (str: string) => BlockHeader
  _fromBufferReader: (br: import('../encoding/types').BufferReader) => BlockHeaderInfo
  fromBufferReader: (br: import('../encoding/types').BufferReader) => BlockHeader
  Constants: { START_OF_HEADER: number, MAX_TIME_OFFSET: number, LARGEST_HASH: BN }
}

/**
 * Block and MerkleBlock.
 *
 * Both carry a header and a set of hashes, and both compute a merkle root —
 * but they are not variants of one type. A Block holds every transaction; a
 * MerkleBlock holds a PARTIAL tree plus a flag bitfield, and its `hashes` are
 * the tree's interior and pruned nodes, not transaction ids. Conflating them
 * would typecheck a caller that treats a partial tree as a complete one.
 */
/** State threaded through _traverseMerkleTree; `txs` accumulates matches. */
export interface MerkleTraversal {
  hashesUsed?: number
  flagBitsUsed?: number
  txs?: string[]
}

/** The plain form of a Block. */
export interface BlockObject {
  header: BlockHeaderObj
  transactions: unknown[]
}

/** The plain form of a MerkleBlock. */
export interface MerkleBlockObject {
  header: BlockHeaderObj
  numTransactions: number
  hashes: string[]
  flags: number[]
}

/** The normalized intermediate the _from* helpers produce. */
export interface BlockInfo {
  header: BlockHeaderValue
  transactions: unknown[]
}

import type BlockHeaderValue = require('./blockheader')
import type TransactionValue = require('../transaction')

export interface Block {
  header: BlockHeaderValue
  transactions: TransactionValue[]

  /** Both are the same value: the header hash, big-endian hex. */
  readonly id: string
  readonly hash: string
  /** Memoized by the id/hash accessor. */
  _id?: string

  toObject: () => BlockObject
  toJSON: () => BlockObject
  toBuffer: () => Buffer
  toString: () => string
  toBufferWriter: (bw?: BufferWriter) => BufferWriter
  getTransactionHashes: () => Buffer[]
  getMerkleTree: () => Buffer[]
  getMerkleRoot: () => Buffer | undefined
  validMerkleRoot: () => boolean
  _getHash: () => Buffer
  inspect: () => string
}

export interface BlockConstructor {
  new (arg?: unknown): Block
  (arg?: unknown): Block
  prototype: Block

  fromObject: (obj: BlockObject) => Block
  fromBuffer: (buf: Buffer) => Block
  fromString: (str: string) => Block
  fromBufferReader: (br: BufferReader) => Block
  fromRawBlock: (data: Buffer | string) => Block
  _from: (arg: BlockObject | Buffer | string) => BlockInfo
  _fromObject: (data: BlockObject) => BlockInfo
  _fromBufferReader: (br: BufferReader) => BlockInfo

  MAX_BLOCK_SIZE: number
  /** Attached by ./index; absent when block.js is required directly. */
  BlockHeader?: typeof import('./blockheader')
  MerkleBlock?: typeof import('./merkleblock')
  Values: { START_OF_BLOCK: number, NULL_HASH: Buffer }
}

export interface MerkleBlock {
  header: BlockHeaderValue
  numTransactions: number
  /** Interior and pruned tree nodes — NOT transaction ids. */
  hashes: string[]
  flags: number[]
  _flagBitsUsed?: number
  _hashesUsed?: number

  toBuffer: () => Buffer
  toBufferWriter: (bw?: BufferWriter) => BufferWriter
  toObject: () => MerkleBlockObject
  toJSON: () => MerkleBlockObject
  validMerkleTree: () => boolean
  /** Misspelled in the shipped API; kept as an alias. */
  filterdTxsHash: () => Buffer | string[] | null
  filteredTxsHash: () => Buffer | string[] | null
  /**
   * Two modes in one function: with `checkForTxs` it collects matched
   * transaction hashes into opts.txs and returns them, otherwise it returns
   * the node hash at that position. The return type is the union because the
   * function genuinely returns both.
   */
  _traverseMerkleTree: (depth: number, pos: number, opts?: MerkleTraversal, checkForTxs?: boolean) => Buffer | string[] | null
  _calcTreeWidth: (height: number) => number
  _calcTreeHeight: () => number
  hasTransaction: (tx: TransactionValue | string) => boolean
}

export interface MerkleBlockConstructor {
  new (arg?: unknown): MerkleBlock
  (arg?: unknown): MerkleBlock
  prototype: MerkleBlock

  fromBuffer: (buf: Buffer) => MerkleBlock
  fromBufferReader: (br: BufferReader) => MerkleBlock
  fromObject: (obj: MerkleBlockObject) => MerkleBlock
  _fromBufferReader: (br: BufferReader) => BlockInfo
}
