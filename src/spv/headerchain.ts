'use strict'
/**
 * SPV block-header chain verification — the confirmations half of the SPV story.
 *
 * verifyTxInclusion proves a tx is in a SUPPLIED header; this proves that header is
 * buried under real work by verifying a chain of consecutive headers: each links to
 * the previous (prevHash), each meets its own proof-of-work target, and (optionally)
 * the chain is anchored at a hash the caller independently trusts.
 *
 * TRUST MODEL — read this. It validates linkage + PER-HEADER proof-of-work, but NOT
 * the difficulty-retargeting schedule. A determined attacker can mine cheap headers
 * at an artificially easy `bits`, so PoW-per-header alone is not sufficient in an
 * adversarial setting. For real assurance pass `o.trustedHash` — a block hash you
 * already trust (from your own node, or a hardcoded checkpoint) that the chain's tip
 * (or anchor) must match; the headers around it are then real work extending a block
 * you trust. Full difficulty-retarget validation is intentionally out of scope here.
 */
import BlockHeader = require('../block/blockheader')
import type { HeaderLike, HeaderChainOpts, HeaderChainResult } from './types'
import type { BlockHeader as BlockHeaderType } from '../block/types'

function rev (b: Buffer): Buffer { return Buffer.from(b).reverse() }

function toHeader (h: HeaderLike): BlockHeaderType {
  if (h != null && typeof (h as BlockHeaderType).validProofOfWork === 'function') return h as BlockHeaderType
  if (Buffer.isBuffer(h)) return BlockHeader.fromBuffer(h)
  if (typeof h === 'string') return BlockHeader.fromBuffer(Buffer.from(h, 'hex'))
  throw new Error('each header must be a BlockHeader, an 80-byte Buffer, or hex')
}

/**
 * @param {Array} headers  consecutive headers, oldest→newest (BlockHeader/Buffer/hex).
 * @param {object} [opts]
 *   requirePow {boolean=true}  verify each header meets its bits target.
 *   trustedHash {string}       a block hash the chain's tip or anchor must equal.
 * @returns {{ valid, reason?, count, anchorHash, tipHash, work }}
 */
function verifyHeaderChain (headers: HeaderLike[], opts?: HeaderChainOpts): HeaderChainResult {
  const o: HeaderChainOpts = opts ?? {}
  if (!Array.isArray(headers) || headers.length === 0) {
    throw new Error('headers must be a non-empty array')
  }
  const hs = headers.map(toHeader)
  const requirePow = o.requirePow !== false
  let work = 0

  for (let i = 0; i < hs.length; i++) {
    // Bound by hs.length, so every index is populated.
    const h = hs[i] as BlockHeaderType
    if (requirePow && !h.validProofOfWork()) {
      return { valid: false, reason: 'invalid proof-of-work at index ' + i, count: hs.length }
    }
    work += h.getDifficulty()
    if (i > 0) {
      const prev = hs[i - 1] as BlockHeaderType
      const linkOk = rev(h.prevHash).toString('hex').toLowerCase() === prev.id.toLowerCase()
      if (!linkOk) {
        return { valid: false, reason: 'broken link at index ' + i, count: hs.length }
      }
    }
  }

  const anchorHash = (hs[0] as BlockHeaderType).id
  const tipHash = (hs[hs.length - 1] as BlockHeaderType).id

  if (o.trustedHash != null) {
    const t = String(o.trustedHash).toLowerCase()
    if (t !== tipHash.toLowerCase() && t !== anchorHash.toLowerCase()) {
      return {
        valid: false,
        reason: 'chain is not anchored at the trusted hash',
        count: hs.length,
        anchorHash,
        tipHash
      }
    }
  }

  return { valid: true, count: hs.length, anchorHash, tipHash, work }
}

const headerchain = { verifyHeaderChain }

export = headerchain
