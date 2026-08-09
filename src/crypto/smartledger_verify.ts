'use strict'

/**
 * SmartLedger Hardened Verification Module
 * Provides secure ECDSA signature verification with malleability protection
 */

import BN = require('./bn')
import Point = require('./point')
import ECDSA = require('./ecdsa')

// Cache curve constants for performance
const n = Point.getN()
const nh = n.shrn(1) // n / 2

/**
 * Hardened signature verification with canonicalization
 * @param {Buffer} msgHash - 32-byte message hash
 * @param {Signature|Buffer} sig - Signature object with r,s components or DER buffer
 * @param {PublicKey} pubkey - Public key for verification
 * @returns {boolean} - true if signature is valid and canonical
 */
function smartVerify (msgHash: any, sig: any, pubkey: any) {
  // Strict input validation
  if (!Buffer.isBuffer(msgHash) || msgHash.length !== 32) {
    throw new Error('Invalid message hash: must be 32-byte buffer')
  }

  if (!sig) {
    return false
  }

  // Parse DER buffer to Signature object if needed
  let sigObj = sig
  if (Buffer.isBuffer(sig)) {
    try {
      const Signature = require('./signature')
      sigObj = Signature.fromDER(sig)
    } catch (e) {
      return false
    }
  }

  if (!sigObj || !sigObj.r || !sigObj.s) {
    return false
  }

  // Ensure r and s are BN instances
  const r = BN.isBN(sigObj.r) ? sigObj.r : new BN(sigObj.r)
  const s = BN.isBN(sigObj.s) ? sigObj.s : new BN(sigObj.s)

  // Reject zero values
  if (r.isZero() || s.isZero()) {
    return false
  }

  // Reject values >= n (curve order)
  if (r.gte(n) || s.gte(n)) {
    return false
  }

  // Reject high-S rather than canonicalizing it: ECDSA accepts s and n-s
  // equally, so verifying a rewritten s would report every malleated signature
  // as valid — the outcome this module exists to prevent.
  if (s.gt(nh)) {
    return false
  }

  const Signature = require('./signature')
  const canonicalSig = new Signature({
    r,
    s
  })

  return ECDSA.verify(msgHash, canonicalSig, pubkey)
}

/**
 * Check if signature is in canonical form (s <= n/2)
 * @param {Object|Buffer} sig - Signature with r,s components or DER buffer
 * @returns {boolean} - true if signature is canonical
 */
function isCanonical (sig: any) {
  if (!sig) {
    return false
  }

  // Parse DER buffer to Signature object if needed
  let sigObj = sig
  if (Buffer.isBuffer(sig)) {
    try {
      const Signature = require('./signature')
      sigObj = Signature.fromDER(sig)
    } catch (e) {
      return false
    }
  }

  if (!sigObj || !sigObj.s) {
    return false
  }

  const s = BN.isBN(sigObj.s) ? sigObj.s : new BN(sigObj.s)
  return s.lte(nh)
}

/**
 * Canonicalize signature to ensure s <= n/2
 * @param {Object} sig - Signature object to canonicalize
 * @returns {Object} - New signature object with canonical s
 */
function canonicalize (sig: any) {
  if (!sig || !sig.r || !sig.s) {
    throw new Error('Invalid signature object')
  }

  const r = BN.isBN(sig.r) ? sig.r : new BN(sig.r)
  const s = BN.isBN(sig.s) ? sig.s : new BN(sig.s)

  let canonicalS = s
  if (s.gt(nh)) {
    canonicalS = n.sub(s)
  }

  return {
    r,
    s: canonicalS
  }
}

export = {
  smartVerify,
  isCanonical,
  canonicalize,
  constants: {
    n,
    nh
  }
}
