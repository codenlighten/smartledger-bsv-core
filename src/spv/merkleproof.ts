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
import Hash = require('../crypto/hash')
import type { MerkleProof, TxInclusionParams, TxInclusionResult } from './types'
import type { BlockHeader as BlockHeaderType } from '../block/types'

const HEX32 = /^[0-9a-fA-F]{64}$/

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
  let header: BlockHeaderType | Buffer | string = params.header
  if (Buffer.isBuffer(header) || typeof header === 'string') {
    header = BlockHeader.fromBuffer(Buffer.isBuffer(header) ? header : Buffer.from(header, 'hex'))
  }
  const hdr = header as BlockHeaderType
  if (hdr?.merkleRoot == null) throw new Error('a valid block header is required')

  const headerRoot = toDisplay(hdr.merkleRoot) // header stores the root internal-LE
  const computed = merkleRootFromBranch(params.txid, params.index, params.nodes)
  const rootMatches = computed.toLowerCase() === headerRoot.toLowerCase()

  const requirePow = params.requirePow !== false
  const powValid = hdr.validProofOfWork()

  return {
    valid: rootMatches && (!requirePow || powValid),
    rootMatches,
    powValid,
    merkleRoot: computed,
    blockHash: hdr.id
  }
}

const merkleproof = {
  merkleRootFromBranch,
  verifyMerkleProof,
  verifyTxInclusion
}

export = merkleproof
