'use strict'
/**
 * SmartContract.PushTx — a correct, interpreter-verified OP_PUSH_TX (nChain
 * WP1605) for Bitcoin SV.
 *
 * The locking script GENERATES an ECDSA signature in-script from a preimage the
 * spender pushed, then OP_CHECKSIG verifies it against a fixed public key.
 * OP_CHECKSIG only passes if the message it derives internally (the genuine
 * BIP-143 sighash of THIS spend) equals HASH256(preimage) — so a passing check
 * proves the pushed preimage IS this transaction, letting a script read and
 * constrain its own spending transaction.
 *
 * Optimal parameters: private key a = 1, ephemeral k = 1  =>  r = Gx,
 *   s = (e + Gx) mod n,  pubkey P = 02||Gx,  e = HASH256(preimage).
 *
 * Requires post-Genesis limits — call SmartContract.enableGenesis() (a.k.a
 * Interpreter.useGenesisLimits()) before verifying these scripts.
 */

import Script = require('../script')
import Opcode = require('../opcode')
import Signature = require('../crypto/signature')
import BN = require('../crypto/bn')
import Hash = require('../crypto/hash')
import H = require('./helpers')
import type { PushTxOptions, GrindOptions } from './types'
import type { Transaction, Output } from '../transaction/types'

const SIGHASH = H.SIGHASH
const scriptNum = H.scriptNum

// secp256k1 constants (big-endian)
const Gx = Buffer.from('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex')
const N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
const PUBKEY = Buffer.concat([Buffer.from([0x02]), Gx]) // compressed P = G (y even)

// script-number (little-endian) forms
const gxLe = Buffer.from(Gx).reverse() // 32B, top 0x79 => positive
const N_LE = Buffer.concat([Buffer.from(N.toBuffer()).reverse(), Buffer.from([0x00])]) // 33B positive

// fixed DER prefix: SEQUENCE(0x44) INTEGER(0x20) r=Gx INTEGER(0x20)
const DER_PREFIX = Buffer.concat([Buffer.from([0x30, 0x44, 0x02, 0x20]), Gx, Buffer.from([0x02, 0x20])])

/** Reverse a fixed n-byte buffer on top of the stack (big-endian <-> little-endian). */
function reverseBytes (script: Script, n: number) {
  let i
  for (i = 0; i < n - 1; i++) script.add(Opcode.OP_1).add(Opcode.OP_SPLIT)
  for (i = 0; i < n - 1; i++) script.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  return script
}

// Common SIGHASH flag combinations (all include FORKID, required on BSV). The
// marketplace/partially-signed pattern uses SINGLE|ANYONECANPAY: the signer commits
// only to its own input and its own output (the output at the same index), leaving
// a counterparty free to add funding inputs and change outputs without invalidating
// the signature.
const SIGHASH_ALL_FORKID = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID // 0x41
const SIGHASH_SINGLE_FORKID = Signature.SIGHASH_SINGLE | Signature.SIGHASH_FORKID // 0x43
const SIGHASH_SINGLE_ANYONECANPAY_FORKID =
  Signature.SIGHASH_SINGLE | Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_FORKID // 0xc3
// ALL|ANYONECANPAY commits to ALL outputs (so the covenant can pin the FULL output
// set) while leaving inputs open for a counterparty to add funding. This is the flag
// the 1Sat Ordinals OrdLock uses: the buyer supplies the surrounding outputs and the
// covenant binds the seller's payment output into the committed hashOutputs.
const SIGHASH_ALL_ANYONECANPAY_FORKID =
  Signature.SIGHASH_ALL | Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_FORKID // 0xc1

/**
 * Append the in-script signature generator + verifier ("PUSH_TX core").
 * Pre:  top of stack = preimage. Post: top = OP_CHECKSIG result.
 *
 * @param {Script} script
 * @param {object} [opts]
 * @param {number} [opts.sighashType=0x41] the SIGHASH flag byte baked into the
 *   synthetic signature. OP_CHECKSIG derives the spend's sighash using THIS flag,
 *   so the spender must push the matching BIP-143 preimage (grind with the same
 *   sighashType). Defaults to SIGHASH_ALL|FORKID — existing covenants are unchanged.
 */
function pushTxCore (script: Script, opts?: PushTxOptions) {
  const sighashType = (opts && opts.sighashType) || SIGHASH
  script.add(Opcode.OP_HASH256) // z = HASH256(preimage), 32B BE
  reverseBytes(script, 32) // -> little-endian = e. The grind guarantees e is
  // already positive and minimally encoded (z[0] in 0x01..0x7f), so NO 0x00 sign
  // byte is appended — keeping the script MINIMALDATA-clean (mainnet-relayable).
  script.add(gxLe).add(Opcode.OP_ADD) // e + Gx
  script.add(N_LE).add(Opcode.OP_MOD) // s = (e + Gx) mod n
  script.add(scriptNum(32)).add(Opcode.OP_NUM2BIN) // s -> 32-byte LE
  reverseBytes(script, 32) // -> big-endian (DER INTEGER body) ; stack: [s_be]
  // Build the DER signature and the pubkey from a SINGLE Gx push (Gx is both the
  // r-value inside the DER prefix and the body of the 02||Gx pubkey). Sharing it
  // via the altstack saves a 32-byte constant vs. embedding Gx twice.
  script.add(Gx).add(Opcode.OP_DUP) // [s_be, Gx, Gx]
  script.add(Opcode.OP_2).add(Opcode.OP_SWAP).add(Opcode.OP_CAT) // pubkey = 02||Gx (OP_2 = minimal push of 0x02)
  script.add(Opcode.OP_TOALTSTACK) // park pubkey ; [s_be, Gx]
  script.add(Buffer.from([0x30, 0x44, 0x02, 0x20])).add(Opcode.OP_SWAP).add(Opcode.OP_CAT) // 30440220||Gx
  script.add(Buffer.from([0x02, 0x20])).add(Opcode.OP_CAT) // ||0220  => DER prefix
  script.add(Opcode.OP_SWAP).add(Opcode.OP_CAT) // DER prefix || s_be
  script.add(Buffer.from([sighashType])).add(Opcode.OP_CAT) // || sighash flag => full DER sig
  script.add(Opcode.OP_FROMALTSTACK).add(Opcode.OP_CHECKSIG) // pubkey ; verify against P = G
  return script
}

/** Bare authenticator script: unlock with the (grindable) preimage. */
function authenticator () {
  return pushTxCore(new Script())
}

/** Extract the committed hashOutputs (item 9, offsetFromEnd 40, len 32) from a preimage on-stack. */
function extractHashOutputs (script: Script) {
  // last 40 bytes, then the first 32 of those = hashOutputs. (BSV string opcodes.)
  script.add(scriptNum(40)).add(Opcode.OP_RIGHT).add(scriptNum(32)).add(Opcode.OP_LEFT)
  return script
}

// The BIP-143 preimage ends with nHashType as a 4-byte LE word; for SIGHASH_ALL|
// FORKID that word is 0x41 00 00 00. assertSighashType builds this word per flag.

/**
 * Assert the spend is SIGHASH_ALL|FORKID (0x41). Pre/Post: top of stack = preimage
 * (left untouched). These covenants read fixed offsets (104 / 52 / 40) that are
 * meaningful only for the 0x41 layout, and the OP_PUSH_TX core already pins the
 * flag implicitly (its synthetic sig carries 0x41, so OP_CHECKSIG only accepts a
 * preimage hashing to the 0x41 sighash). Note the offsets themselves are invariant
 * in the number of INPUTS — hashPrevouts/hashSequence are digests of all inputs,
 * so the preimage is the same length for 1 or N inputs; the covenant simply does
 * not constrain sibling inputs, by design. What it does assume is a single
 * recreated OUTPUT (HASH256(nextOutput) == hashOutputs). This guard makes the
 * flag assumption explicit and fails fast — and survives any refactor of the core.
 */
function assertSighashAll (script: Script) {
  return assertSighashType(script, SIGHASH)
}

/**
 * Assert the spend uses a specific SIGHASH flag. Pre/Post: top of stack = preimage
 * (left untouched). The BIP-143 preimage's trailing 4-byte LE nHashType word must
 * equal `sighashType`. Use with pushTxCore({ sighashType }) + grind({ sighashType })
 * to build covenants under SIGHASH_SINGLE|ANYONECANPAY (marketplace) etc.
 */
function assertSighashType (script: Script, sighashType: number) {
  const word = Buffer.from([sighashType & 0xff, 0x00, 0x00, 0x00])
  script.add(Opcode.OP_DUP).add(scriptNum(4)).add(Opcode.OP_RIGHT)
    .add(word).add(Opcode.OP_EQUALVERIFY)
  return script
}

/** BIP-143 hashOutputs (SIGHASH_ALL) for a set of Transaction.Output objects. */
function hashOutputs (outputs: Output[]) {
  const ser = Buffer.concat(outputs.map(function (o: any) { return o.toBufferWriter().toBuffer() }))
  return Hash.sha256sha256(ser)
}

/**
 * Value/output covenant: the spend is valid only if its outputs hash to
 * `expectedHashOutputs` — coins can only go where the covenant says.
 */
function valueCovenant (expectedHashOutputs: Buffer) {
  const script = new Script().add(Opcode.OP_DUP)
  pushTxCore(script)
  script.add(Opcode.OP_VERIFY)
  extractHashOutputs(script)
  script.add(Buffer.from(expectedHashOutputs)).add(Opcode.OP_EQUAL)
  return script
}

// floor(n/2) — the canonical low-S boundary (matches Signature.hasLowS()).
const HALF_N = new BN('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex')

/**
 * Compute s = (HASH256(preimage)+Gx) mod n; return its 32-byte BE form, or null
 * if the resulting signature would not be a clean, CANONICAL (low-S) DER.
 * Requiring s <= n/2 makes the in-script signature non-malleable and standard,
 * so it passes nodes enforcing SCRIPT_VERIFY_LOW_S — at zero script-size cost
 * (the burden is on the spender's grind, not extra opcodes).
 */
function sFromPreimage (preimage: Buffer) {
  const z = Hash.sha256sha256(preimage)
  // Script no longer sign-extends z, so e (= reverse(z) as a number) must be
  // positive AND minimally encoded: its little-endian MSB (= z[0]) in 0x01..0x7f.
  // This keeps the locking script MINIMALDATA-clean (mainnet-relayable).
  if (z[0]! < 0x01 || z[0]! > 0x7f) return null
  const s = new BN(z).add(new BN(Gx)).mod(N)
  if (s.gt(HALF_N)) return null // enforce low-S (canonical / non-malleable)
  // BUG, PRESERVED: this is bn.js's NATIVE toBuffer(endian, length) signature,
  // but crypto/bn REPLACES toBuffer with an options-object form. 'be' lands in
  // `opts`, `opts.size` is undefined, and the result is the natural-length
  // buffer — 31 bytes or fewer whenever s < 2^248, about 1 call in 256.
  // DER_PREFIX ends in 0220, declaring s to be exactly 32 bytes, and grind()
  // only tests this for truthiness, so it will happily return a nonce whose
  // covenant cannot be spent. The fix is `s.toBuffer({ size: 32 })`.
  // Left as-is: this conversion changes no behaviour. Recorded separately.
  const sBE = (s as any).toBuffer('be', 32)
  return (sBE[0]! >= 0x01) ? sBE : null // s <= n/2 already guarantees sBE[0] <= 0x7f
}

/**
 * Grind a malleable field of the spend until the in-script OP_PUSH_TX signature
 * is a clean, canonical (low-S) fixed-length DER. Returns { preimage, tries,
 * field, nonce }; mutates the chosen field on `spend`.
 *
 * @param {object} [opts] grind options (a bare number is accepted as legacy maxTries):
 *   - maxTries {number}  attempts before giving up (default 5000).
 *   - start    {number}  first nonce value to try (default 0).
 *   - field    {'nLockTime'|'sequence'}  which field carries the grind nonce
 *       (default 'nLockTime'). Use 'sequence' when the covenant pins nLockTime for
 *       a real CLTV absolute timelock: the input's sequence is swept down from
 *       0xfffffffe (kept non-final, so CLTV still triggers) instead of clobbering
 *       nLockTime. (Not for CSV/relative-locktime covenants, which encode meaning
 *       in the sequence number itself.)
 */
function grind (spend: Transaction, inputIndex: number, lockingScript: Script, satoshis: number, opts?: number | GrindOptions) {
  if (typeof opts === 'number') opts = { maxTries: opts } // back-compat: legacy maxTries arg
  opts = opts || {}
  const maxTries = opts.maxTries || 5000
  const start = opts.start || 0
  const field = opts.field || 'nLockTime'
  const sighashType = opts.sighashType || SIGHASH
  if (field !== 'nLockTime' && field !== 'sequence') {
    throw new Error("grind field must be 'nLockTime' or 'sequence'")
  }
  const input = spend.inputs[inputIndex]!
  for (let i = 0; i < maxTries; i++) {
    const nonce = start + i
    if (field === 'nLockTime') spend.nLockTime = nonce
    else input.sequenceNumber = 0xfffffffe - nonce // stay < 0xffffffff (non-final)
    const preimage = H.rawPreimage(spend, inputIndex, lockingScript, satoshis, sighashType)
    if (sFromPreimage(preimage)) return { preimage, tries: i + 1, field, nonce }
  }
  throw new Error('OP_PUSH_TX grind failed after ' + maxTries + ' tries')
}

export = {
  Gx,
  N,
  PUBKEY,
  gxLe,
  N_LE,
  DER_PREFIX,
  reverseBytes,
  pushTxCore,
  authenticator,
  extractHashOutputs,
  assertSighashAll,
  assertSighashType,
  SIGHASH_ALL_FORKID,
  SIGHASH_SINGLE_FORKID,
  SIGHASH_SINGLE_ANYONECANPAY_FORKID,
  SIGHASH_ALL_ANYONECANPAY_FORKID,
  hashOutputs,
  valueCovenant,
  sFromPreimage,
  grind
}
