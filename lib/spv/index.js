'use strict'
/**
 * SPV — trustless Simplified Payment Verification helpers.
 *
 * Currently: Merkle inclusion proofs (verify a tx is in a PoW-backed block without
 * a full node). Built on the fork's BlockHeader / MerkleBlock primitives.
 */
const merkleproof = require('./merkleproof')
const headerchain = require('./headerchain')

module.exports = {
  merkleRootFromBranch: merkleproof.merkleRootFromBranch,
  verifyMerkleProof: merkleproof.verifyMerkleProof,
  verifyTxInclusion: merkleproof.verifyTxInclusion,
  verifyHeaderChain: headerchain.verifyHeaderChain
}
