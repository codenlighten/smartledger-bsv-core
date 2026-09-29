'use strict'
/**
 * SPV Merkle inclusion proofs.
 *
 * Trustlessly verify that a transaction is included in a block, given a Merkle
 * branch proof and a trusted block header — no full node and no trust in the data
 * provider. This is the real inclusion check that replaces the "trust the caller's
 * txData" anchor stubs: a provider (explorer / node) can lie about a tx being mined,
 * but it cannot forge a Merkle branch that hashes to a proof-of-work-backed header's
 * merkle root.
 *
 * Byte order: `txid`, branch `nodes` and `merkleRoot` are DISPLAY-order hex (big
 * endian, as block explorers show them). Bitcoin hashes internally in little-endian,
 * so we reverse on the way in/out. Nodes are combined with double-SHA256, matching
 * lib/block/{block,merkleblock}.js. A node of '*' (or '' / null) means "duplicate the
 * working hash" — Bitcoin's odd-node rule, per the TSC Merkle Proof standard.
 */
import BlockHeader = require('../block/blockheader')
import BN = require('../crypto/bn')
import Hash = require('../crypto/hash')
import type { MerkleProof, TxInclusionParams, TxInclusionResult } from './types'
import type { BlockHeader as BlockHeaderType } from '../block/types'

const HEX32 = /^[0-9a-fA-F]{64}$/

// 2^256, for turning a target into the work it represents.
const TWO_256 = BlockHeader.Constants.LARGEST_HASH

/**
 * The easiest target a header may declare and still be believed: difficulty 1,
 * 0x1d00ffff, the proof-of-work limit of both mainnet and testnet. Regtest headers declare
 * 0x207fffff and are only checked when a caller asks for that limit.
 */
const POW_LIMIT_BITS = 0x1d00ffff

/**
 * A compact target (`bits`) as a BN, or null if the encoding is one no header may use.
 *
 * Transcribed from Bitcoin's arith_uint256::SetCompact and CheckProofOfWork: negative, zero
 * and overflowing targets are refused, and the word is SHIFTED BEFORE those tests read it,
 * as the node does. BlockHeader.getTargetDifficulty implements none of these rules and
 * shifts the wrong way below size 4, so it is not used here.
 */
function targetFromBits (bits: number): BN | null {
  const size = bits >>> 24
  let word = bits & 0x007fffff
  let target: BN
  if (size <= 3) {
    word = word >>> (8 * (3 - size))
    target = new BN(word)
  } else {
    target = new BN(word).shln(8 * (size - 3))
  }
  if (word === 0) return null
  if ((bits & 0x00800000) !== 0) return null
  if ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32)) return null
  return target
}

/** The work a target represents: 2^256 / (target + 1). Difficulty 1 is about 4.295e9. */
function workFromTarget (target: BN): BN {
  return TWO_256.div(target.add(new BN(1)))
}

/** The limit as a target, refusing anything parseInt would read only part of. */
function targetLimit (powLimit?: number | string | BN | null): BN {
  if (powLimit === undefined || powLimit === null) powLimit = POW_LIMIT_BITS
  // A BN is the target itself, and still has to be a target: 2^256 or above is not a limit
  // at all — every target is below it, so the cap would admit the free forgery it exists to
  // stop — and zero admits nothing.
  if (BN.isBN(powLimit)) {
    const bn = powLimit as BN
    if (bn.isNeg() || bn.isZero() || bn.cmp(TWO_256) >= 0) {
      throw new Error('powLimit as a BN must be a target above zero and below 2^256')
    }
    return bn
  }
  let bits: number
  if (typeof powLimit === 'string') {
    if (!/^(0x)?[0-9a-fA-F]{1,8}$/.test(powLimit)) {
      throw new Error('powLimit must be compact bits as hex, a uint32, or a BN target, not ' +
        JSON.stringify(powLimit))
    }
    bits = parseInt(powLimit.replace(/^0x/, ''), 16)
  } else if (typeof powLimit === 'number' && Number.isInteger(powLimit) &&
    powLimit >= 0 && powLimit <= 0xffffffff) {
    bits = powLimit
  } else {
    throw new Error('powLimit must be compact bits as hex, a uint32, or a BN target, not ' +
      JSON.stringify(powLimit))
  }
  const target = targetFromBits(bits)
  if (target === null) throw new Error('powLimit is not a usable compact target: ' + String(powLimit))
  return target
}

/**
 * A floor given in DIFFICULTY as the work it means: difficulty x 4,295,032,833, exactly.
 *
 * `minWork` counts hashes, and difficulty is the unit people quote — a real BSV header is
 * "difficulty 2.6e10", not "1.1e20 hashes". Reading one as the other sets a floor 4.3 billion
 * times too low and fails OPEN, which is why the unit is in the name. The multiplication is
 * done on integers so a fractional difficulty keeps its digits instead of drifting.
 */
function workFromDifficulty (difficulty: number | string): BN {
  let text = typeof difficulty === 'number' ? numberToDecimal(difficulty) : String(difficulty)
  // `1e19` is how a floor this size is written, by hand and by JSON, so both a Number and a
  // string may arrive in exponent form. Expanded by moving the point, never through a float.
  if (/^[0-9]+(\.[0-9]+)?[eE][+]?[0-9]+$/.test(text)) text = expandExponent(text)
  if (!/^[0-9]+(\.[0-9]+)?$/.test(text)) {
    throw new Error('minDifficulty must be a non-negative decimal number, not ' +
      JSON.stringify(difficulty))
  }
  const parts = text.split('.')
  const frac = parts[1] ?? ''
  const scaled = new BN((parts[0] as string) + frac, 10)
    .mul(workFromTarget(targetFromBits(POW_LIMIT_BITS) as BN))
  return frac.length > 0 ? scaled.div(new BN(10).pow(new BN(frac.length))) : scaled
}

/** `2.557e10` as `25570000000`, by moving the decimal point, with no float in the path. */
function expandExponent (text: string): string {
  const halves = text.split(/[eE]/)
  const exp = parseInt((halves[1] as string).replace('+', ''), 10)
  const digits = (halves[0] as string).split('.')
  const intPart = digits[0] as string
  const frac = digits[1] ?? ''
  if (exp >= frac.length) return intPart + frac + '0'.repeat(exp - frac.length)
  return intPart + frac.slice(0, exp) + '.' + frac.slice(exp)
}

/** A Number as plain decimal digits, so 2.6e10 does not reach the parser as "2.6e+10". */
function numberToDecimal (n: number): string {
  if (!Number.isFinite(n) || n < 0) {
    throw new Error('minDifficulty must be a non-negative finite number, not ' + String(n))
  }
  if (!/e/i.test(String(n))) return String(n)
  return n.toLocaleString('en-US', { useGrouping: false, maximumFractionDigits: 20 })
}

/**
 * `minWork` as a BN, refusing anything bn.js would read loosely: it parses 1e21 as 23521,
 * '4.3e9' as 4 and 'abc' as 1122, so a floor set from a Number near the chain's work would
 * silently become a few thousand — a floor nothing fails.
 */
function minWorkBN (minWork: number | string | BN): BN {
  if (BN.isBN(minWork)) {
    if ((minWork as BN).isNeg()) throw new Error('minWork as a BN must not be negative')
    return minWork as BN
  }
  if (typeof minWork === 'number') {
    if (!Number.isSafeInteger(minWork) || minWork < 0) {
      throw new Error('minWork as a number must be a non-negative safe integer; for larger ' +
        'floors pass a decimal string or a BN, not ' + String(minWork))
    }
    return new BN(String(minWork), 10)
  }
  if (typeof minWork === 'string' && /^[0-9]+$/.test(minWork)) return new BN(minWork, 10)
  throw new Error('minWork must be a non-negative integer, a decimal string or a BN, not ' +
    JSON.stringify(minWork))
}

/**
 * Exactly 80 bytes of header, re-parsed, so every checked field comes from one snapshot.
 * An object that merely states a merkleRoot is refused: believing it is the trust the
 * protocol removes.
 */
function headerSnapshot (header: unknown): BlockHeaderType {
  let buf: Buffer | undefined
  if (Buffer.isBuffer(header)) buf = header
  else if (typeof header === 'string') {
    // Buffer.from stops at the first non-hex character, so 160 good characters followed by
    // junk would arrive as a clean 80 bytes.
    if (!/^[0-9a-fA-F]{160}$/.test(header)) {
      throw new Error('a block header as hex must be exactly 160 hex characters')
    }
    buf = Buffer.from(header, 'hex')
  } else if (header != null && typeof (header as BlockHeaderType).toBuffer === 'function') {
    buf = (header as BlockHeaderType).toBuffer()
  } else {
    throw new Error('a block header must be 80 bytes, as hex, a Buffer or a BlockHeader; ' +
      'an object stating a merkleRoot is not a header and cannot be checked')
  }
  if (!Buffer.isBuffer(buf) || buf.length !== 80) {
    throw new Error('a block header must be exactly 80 bytes, not ' +
      (Buffer.isBuffer(buf) ? String(buf.length) : typeof buf))
  }
  return BlockHeader.fromBuffer(buf) as BlockHeaderType
}

function rev (buf: Buffer): Buffer { return Buffer.from(buf).reverse() }
function toInternal (hex: string): Buffer { return rev(Buffer.from(hex, 'hex')) } // display -> internal LE
function toDisplay (buf: Buffer): string { return rev(buf).toString('hex') } // internal LE -> display

/**
 * Recompute the Merkle root from a branch proof.
 * @param {string} txid       display-order txid hex (64 hex chars)
 * @param {number} index      0-based position of the tx within the block
 * @param {Array<string>} nodes sibling hashes, leaf->root (display hex; '*' = duplicate)
 * @returns {string} the computed merkle root (display-order hex)
 */
function merkleRootFromBranch (txid: string, index: number, nodes?: string[]): string {
  if (!HEX32.test(String(txid))) throw new Error('txid must be 32-byte hex')
  if (!Number.isInteger(index) || index < 0) throw new Error('index must be a non-negative integer')
  const ns = nodes ?? []
  let cur = toInternal(txid)
  let idx = index
  for (let i = 0; i < ns.length; i++) {
    const node = ns[i]
    let sib: Buffer
    if (node === '*' || node === '' || node == null) {
      sib = cur // odd-node: the working hash is duplicated
    } else {
      if (!HEX32.test(String(node))) throw new Error('proof node ' + i + ' must be 32-byte hex or "*"')
      sib = toInternal(node)
    }
    // idx even -> current is the LEFT child; idx odd -> current is the RIGHT child.
    cur = (idx & 1)
      ? Hash.sha256sha256(Buffer.concat([sib, cur]))
      : Hash.sha256sha256(Buffer.concat([cur, sib]))
    idx = Math.floor(idx / 2)
  }
  return toDisplay(cur)
}

/**
 * Verify a Merkle branch proof against an expected root.
 * @param {object} proof { txid, index, nodes, merkleRoot } (all display-order hex)
 * @returns {boolean}
 */
function verifyMerkleProof (proof: MerkleProof): boolean {
  if (proof?.merkleRoot == null) throw new Error('proof.merkleRoot is required')
  const computed = merkleRootFromBranch(proof.txid, proof.index, proof.nodes)
  return computed.toLowerCase() === String(proof.merkleRoot).toLowerCase()
}

/**
 * Verify a transaction is included in a block: branch -> root, root ==
 * header.merkleRoot, and (unless disabled) the header meets its PoW target.
 *
 * NOTE: this proves inclusion in the SUPPLIED header. Confirming that header is on
 * the honest chain (height / confirmations) requires a trusted header chain, which
 * the caller supplies out of band.
 *
 * @param {object} params { txid, index, nodes, header, requirePow=true }
 *   header: a bsv.BlockHeader, an 80-byte Buffer, or 80-byte hex.
 * @returns {{ valid:boolean, rootMatches:boolean, powValid:boolean, merkleRoot:string, blockHash:string }}
 */
function verifyTxInclusion (params: TxInclusionParams): TxInclusionResult {
  const hdr = headerSnapshot(params.header)

  const headerRoot = toDisplay(hdr.merkleRoot) // the root as the header's own bytes give it
  const computed = merkleRootFromBranch(params.txid, params.index, params.nodes)
  const rootMatches = computed.toLowerCase() === headerRoot.toLowerCase()

  const requirePow = params.requirePow !== false
  const target = targetFromBits(hdr.bits)
  const powValid = target !== null && new BN(hdr.id, 'hex').cmp(target) <= 0
  const work = target === null ? new BN(0) : workFromTarget(target)
  // Both are policy the caller supplies, so neither is read — nor rejected as malformed —
  // when the work checks are off.
  const targetAllowed = target !== null &&
    (!requirePow || target.cmp(targetLimit(params.powLimit)) <= 0)
  let floor: BN | null = null
  if (requirePow) {
    // One floor, named for its unit. Accepting both would leave the caller guessing which one
    // bit, and the two are 4.3e9 apart.
    const hasWork = params.minWork !== undefined && params.minWork !== null
    const hasDifficulty = params.minDifficulty !== undefined && params.minDifficulty !== null
    if (hasWork && hasDifficulty) {
      throw new Error('pass minWork (hashes) or minDifficulty (difficulty), not both')
    }
    if (hasWork) floor = minWorkBN(params.minWork as number | string | BN)
    else if (hasDifficulty) floor = workFromDifficulty(params.minDifficulty as number | string)
  }
  const workSufficient = floor === null || work.cmp(floor) >= 0

  return {
    valid: rootMatches && (!requirePow || (powValid && targetAllowed && workSufficient)),
    rootMatches,
    powValid,
    targetAllowed,
    workSufficient,
    work: work.toString(10),
    merkleRoot: computed,
    blockHash: hdr.id
  }
}

const merkleproof = {
  POW_LIMIT_BITS,
  merkleRootFromBranch,
  verifyMerkleProof,
  verifyTxInclusion,
  // Internal to src/spv: headerchain applies the same cap. Not re-exported by SPV.
  targetFromBits,
  targetLimit,
  workFromTarget,
  workFromDifficulty,
  headerSnapshot
}

export = merkleproof
