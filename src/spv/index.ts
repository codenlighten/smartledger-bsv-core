'use strict'
/**
 * SPV — trustless Simplified Payment Verification helpers.
 *
 * Currently: Merkle inclusion proofs (verify a tx is in a PoW-backed block
 * without a full node). Built on the BlockHeader / MerkleBlock primitives.
 */
import merkleproof = require('./merkleproof')
import headerchain = require('./headerchain')

const SPV = {
  POW_LIMIT_BITS: merkleproof.POW_LIMIT_BITS,
  merkleRootFromBranch: merkleproof.merkleRootFromBranch,
  verifyMerkleProof: merkleproof.verifyMerkleProof,
  verifyTxInclusion: merkleproof.verifyTxInclusion,
  verifyHeaderChain: headerchain.verifyHeaderChain
}

export = SPV
