/**
 * Shapes for the block modules.
 *
 * Separate from the implementation because blockheader.ts uses `export =` to
 * keep its CommonJS `require()` shape, and TypeScript forbids an export
 * assignment alongside other exported members.
 */
import type BN = require('bn.js')
import type { BufferWriter } from '../encoding/types'

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
