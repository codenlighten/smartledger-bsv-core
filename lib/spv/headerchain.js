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
 * adversarial setting. For real assurance pass `opts.trustedHash` — a block hash you
 * already trust (from your own node, or a hardcoded checkpoint) that the chain's tip
 * (or anchor) must match; the headers around it are then real work extending a block
 * you trust. Full difficulty-retarget validation is intentionally out of scope here.
 */
const BlockHeader = require('../block/blockheader')

function rev (b) { return Buffer.from(b).reverse() }

function toHeader (h) {
  if (h && typeof h.validProofOfWork === 'function') return h
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
function verifyHeaderChain (headers, opts) {
  opts = opts || {}
  if (!Array.isArray(headers) || headers.length === 0) {
    throw new Error('headers must be a non-empty array')
  }
  const hs = headers.map(toHeader)
  const requirePow = opts.requirePow !== false
  let work = 0

  for (let i = 0; i < hs.length; i++) {
    if (requirePow && !hs[i].validProofOfWork()) {
      return { valid: false, reason: 'invalid proof-of-work at index ' + i, count: hs.length }
    }
    work += hs[i].getDifficulty()
    if (i > 0) {
      const linkOk = rev(hs[i].prevHash).toString('hex').toLowerCase() === hs[i - 1].id.toLowerCase()
      if (!linkOk) {
        return { valid: false, reason: 'broken link at index ' + i, count: hs.length }
      }
    }
  }

  const anchorHash = hs[0].id
  const tipHash = hs[hs.length - 1].id

  if (opts.trustedHash) {
    const t = String(opts.trustedHash).toLowerCase()
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

module.exports = { verifyHeaderChain }
