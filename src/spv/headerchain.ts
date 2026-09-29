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
import BN = require('../crypto/bn')
import merkleproof = require('./merkleproof')
import type { HeaderLike, HeaderChainOpts, HeaderChainResult } from './types'
import type { BlockHeader as BlockHeaderType } from '../block/types'

function rev (b: Buffer): Buffer { return Buffer.from(b).reverse() }

// Every header goes through the same 80-byte snapshot verifyTxInclusion uses, so a chain
// cannot be built from objects that merely claim a prevHash, an id and a passing
// validProofOfWork().
function toHeader (h: HeaderLike): BlockHeaderType {
  return merkleproof.headerSnapshot(h)
}

/**
 * @param {Array} headers  consecutive headers, oldest→newest (BlockHeader/Buffer/hex).
 * @param {object} [opts]
 *   requirePow {boolean=true}  verify each header meets its bits target.
 *   powLimit {number|string}   easiest target a header may declare, as compact bits.
 *                              Default 0x1d00ffff; regtest headers need 0x207fffff.
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
  const limit = requirePow ? merkleproof.targetLimit(o.powLimit) : null
  let work = 0

  for (let i = 0; i < hs.length; i++) {
    // Bound by hs.length, so every index is populated.
    const h = hs[i] as BlockHeaderType
    // The declared target, read the way the node reads it. validProofOfWork() would use
    // BlockHeader.getTargetDifficulty, which disagrees with this below size 4, so the hash
    // test and the limit test would be against two different targets.
    const declared = merkleproof.targetFromBits(h.bits)
    if (requirePow) {
      if (declared === null || new BN(h.id, 'hex').cmp(declared) > 0) {
        return { valid: false, reason: 'invalid proof-of-work at index ' + i, count: hs.length }
      }
      // Work against a target the header chose for itself is not work. Without this, a
      // chain mined at bits 0x2100ffff costs nothing and links perfectly.
      if (declared.cmp(limit as BN) > 0) {
        return {
          valid: false,
          reason: 'target easier than the proof-of-work limit at index ' + i,
          count: hs.length
        }
      }
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
