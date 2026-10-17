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
  const ser = Buffer.concat(outputs.map(function (o: Output) { return o.toBufferWriter().toBuffer() }))
  return Hash.sha256sha256(ser)
}

/**
 * Value/output covenant: the spend is valid only if its outputs hash to
 * `expectedHashOutputs` — coins can only go where the covenant says.
 *
 * This pins the digest of the ENTIRE output set under SIGHASH_ALL — count, order,
 * values and scripts — so exactly ONE output set is admissible. In particular there
 * is no room for a change output unless you pin that too: a lock built from
 * `hashOutputs([payout])` rejects the spend `[payout, change]`. Pinning change fixes
 * its AMOUNT, not the fee, because extra inputs raise the input value while the
 * outputs stay identical.
 *
 * To bind one output and leave the rest free, use `valueCovenantSingle` — which pins
 * the output at the spending INPUT's index, not one you choose, and leaves every
 * other output unconstrained. To allow arbitrary change under SIGHASH_ALL, the
 * spender has to push the change output's serialization so the script can rebuild and
 * hash the whole output list itself; this function offers no free-form change
 * facility.
 */
function valueCovenant (expectedHashOutputs: Buffer) {
  const script = new Script().add(Opcode.OP_DUP)
  pushTxCore(script)
  script.add(Opcode.OP_VERIFY)
  extractHashOutputs(script)
  script.add(Buffer.from(expectedHashOutputs)).add(Opcode.OP_EQUAL)
  return script
}

/**
 * Output covenant under SIGHASH_SINGLE: the spend is valid only if the output AT THE
 * SPENDING INPUT'S OWN INDEX is the one pinned here. Unlike `valueCovenant`, it says
 * nothing about the transaction's other outputs, which is what makes it composable —
 * several such locks can be spent in one transaction, each pinning its own output.
 *
 * `pinned` is a Transaction.Output, or its 32-byte hashOutputs digest if you already
 * have it.
 *
 * Two things here are easy to get wrong, which is why this helper exists rather than
 * leaving callers to compose it:
 *
 *   1. The ORDER. `pushTxCore` consumes the preimage copy it checks, so the sighash
 *      flag has to be asserted while a copy is still on the stack. Appending
 *      `assertSighashType` after the covenant body leaves it nothing to read, and the
 *      resulting lock fails the HONEST spend.
 *   2. An ALL-ZERO pin. 32 zero bytes is not a digest: it is the value BIP-143 puts in
 *      hashOutputs when the input's index is out of range under SIGHASH_SINGLE, i.e.
 *      when there is no output at that index. A lock pinned to it is satisfied by a
 *      spend with NO outputs at all, so it pins nothing while looking like it pins
 *      something. Refused at construction.
 */
function valueCovenantSingle (pinned: Output | Buffer, opts?: { sighashType?: number }): Script {
  const o = opts ?? {}
  const sighashType = o.sighashType === undefined ? SIGHASH_SINGLE_FORKID : o.sighashType
  // A WHITELIST, not a mask test. `(sighashType & 0x1f) !== SIGHASH_SINGLE` admitted 0x03 —
  // SIGHASH_SINGLE without FORKID — and anything carrying stray high bits. Those do not fail
  // loudly: pushTxCore's synthetic signature commits to the flag word, so the lock simply
  // refuses the honest spend, at the same byte count, which is the exact class of silent
  // mistake this helper exists to prevent. The sighash byte has a base type in its low five
  // bits plus ANYONECANPAY (0x80) and FORKID (0x40), so with SINGLE and FORKID both required
  // there are exactly two legal words, and naming them is clearer than deriving them.
  if (sighashType !== SIGHASH_SINGLE_FORKID &&
      sighashType !== SIGHASH_SINGLE_ANYONECANPAY_FORKID) {
    throw new Error('valueCovenantSingle needs SIGHASH_SINGLE|FORKID (0x' +
      SIGHASH_SINGLE_FORKID.toString(16) + ') or SIGHASH_SINGLE|ANYONECANPAY|FORKID (0x' +
      SIGHASH_SINGLE_ANYONECANPAY_FORKID.toString(16) + '); got ' +
      (typeof sighashType === 'number' ? '0x' + (sighashType >>> 0).toString(16) : typeof sighashType) +
      '. Use valueCovenant for SIGHASH_ALL.')
  }
  // Structural, not `instanceof Output`: the Output type is imported here as a TYPE only,
  // and a runtime import would close a cycle (see scripts/check-cycle-safety.js).
  // `toBufferWriter` alone is too weak a discriminator — plenty of unrelated objects carry
  // one — so the two fields hashOutputs actually serialises are required too.
  const asOutput = pinned as Output
  const looksLikeOutput = Boolean(pinned) && typeof asOutput.toBufferWriter === 'function' &&
    asOutput.script !== undefined && asOutput.satoshis !== undefined
  const expected = Buffer.isBuffer(pinned)
    ? pinned
    : looksLikeOutput ? hashOutputs([asOutput]) : null
  if (!expected || expected.length !== 32) {
    throw new Error('valueCovenantSingle needs a Transaction.Output (with script and ' +
      'satoshis), or its 32-byte hashOutputs digest; got ' +
      (expected ? expected.length + ' bytes' : typeof pinned))
  }
  let allZero = true
  for (let i = 0; i < 32; i++) if (expected[i] !== 0) { allZero = false; break }
  if (allZero) {
    throw new Error('valueCovenantSingle refuses an all-zero pin: under SIGHASH_SINGLE that ' +
      'is the hashOutputs of an out-of-range input index, so the lock would be spendable ' +
      'with no outputs at all. Pin a real output.')
  }
  const script = new Script().add(Opcode.OP_DUP)
  assertSighashType(script, sighashType)
  pushTxCore(script, { sighashType })
  script.add(Opcode.OP_VERIFY)
  extractHashOutputs(script)
  script.add(Buffer.from(expected)).add(Opcode.OP_EQUAL)
  return script
}

/**
 * `a = 2^248 * Gx^-1 mod n`, the scalar that makes the compact gate work. Because
 * `Gx * a == 2^248 (mod n)`, the in-script sum becomes `s = e + 2^248` — and in a 32-byte
 * BIG-ENDIAN string `2^248` is exactly `byte[0] = 0x01`, the one place where big-endian and
 * little-endian agree. So the addition is "increment the most significant byte" and both
 * 32-byte reversals vanish.
 *
 * Exported so the embedded public key is VERIFIABLE as `a*G` rather than trusted: the test
 * derives this scalar from the modular inverse rather than reading this constant, so a typo
 * here fails the suite instead of shipping a gate nobody can spend.
 */
const A_SCALAR = new BN('d475289d7db690543c1ecbd9ed0d6c9a2e5920ecebf361bdcca0d61f77af4839', 16)

/** `a*G` compressed — the compact gate's public key. Its private half is A_SCALAR, published. */
const COMPACT_PUBKEY = Buffer.from('02b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0', 'hex')

/**
 * The compact OP_PUSH_TX gate: 89 bytes and 12 counted opcodes, against `pushTxCore`'s 377
 * and 202. Both 124-byte reversals and the 256-bit modular addition are gone, replaced by an
 * increment of one byte.
 *
 *     OP_HASH256 OP_1 OP_SPLIT OP_SWAP OP_BIN2NUM OP_1ADD OP_1 OP_NUM2BIN OP_SWAP OP_CAT
 *     <DER_PREFIX> OP_SWAP OP_CAT <flag> OP_CAT <COMPACT_PUBKEY> OP_CHECKSIG
 *
 * The consequence that matters more than the size: scriptCode rides INSIDE the preimage, so a
 * smaller gate makes a smaller preimage — 246 bytes against 536, under the 520-byte
 * pre-Genesis element cap. Shrinking the script shrinks its own input back under the limit
 * that excluded it, so this gate runs where the classic one cannot.
 *
 * Security: `a` is published and that is safe, because the only `OP_CHECKSIG` consumes a
 * signature the LOCKING script assembles from constants plus the computed `s`, never a
 * spender's. What a passing check establishes is narrower than it looks — equality of
 * `HASH256(preimage)` with the interpreter's sighash is the intended and only readily
 * attainable way to pass, but ECDSA accepts `s` and `n - s` and `r` is fixed, so it is a
 * ~2^128 assumption rather than an identity. **Never use `COMPACT_PUBKEY` as an authorization
 * key**, and keep field reads AFTER the gate.
 */
function pushTxCoreCompact (script: Script, opts?: PushTxOptions) {
  const sighashType = (opts && opts.sighashType) || SIGHASH
  script.add(Opcode.OP_HASH256)
  script.add(Opcode.OP_1).add(Opcode.OP_SPLIT)
  script.add(Opcode.OP_SWAP)
  script.add(Opcode.OP_BIN2NUM).add(Opcode.OP_1ADD)
  script.add(Opcode.OP_1).add(Opcode.OP_NUM2BIN)
  script.add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  script.add(DER_PREFIX).add(Opcode.OP_SWAP).add(Opcode.OP_CAT)
  script.add(Buffer.from([sighashType])).add(Opcode.OP_CAT)
  script.add(COMPACT_PUBKEY).add(Opcode.OP_CHECKSIG)
  return script
}

/** The compact gate alone, as a standalone locking script. 89 bytes. */
function authenticatorCompact () {
  return pushTxCoreCompact(new Script())
}

/**
 * `hashOutputs` extraction with **Monolith-era opcodes only**, so it works on a chain that has
 * activated neither Genesis nor Chronicle. `extractHashOutputs` is 6 bytes but uses
 * `OP_RIGHT`/`OP_LEFT`, which Chronicle restored and which are SILENT NO-OPS before it — so a
 * covenant built on it fails closed pre-Chronicle rather than running. Ten bytes instead of
 * six: four bytes to drop an era dependency.
 *
 *     OP_SIZE <40> OP_SUB OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
 */
function extractHashOutputsPortable (script: Script) {
  script.add(Opcode.OP_SIZE)
  script.add(Buffer.from([40])).add(Opcode.OP_SUB)
  script.add(Opcode.OP_SPLIT).add(Opcode.OP_NIP)
  script.add(Buffer.from([32])).add(Opcode.OP_SPLIT).add(Opcode.OP_DROP)
  return script
}

/**
 * `valueCovenant` with no era dependency: the compact gate plus the portable extraction.
 * **135 bytes with a 292-byte preimage**, verifying with NEITHER Genesis NOR Chronicle active,
 * where the classic 419-byte equivalent needs both.
 *
 * Same semantics as `valueCovenant`: it pins the digest of the ENTIRE output set under
 * SIGHASH_ALL, so exactly one output set is admissible. Grind with `{ form: 'compact' }`.
 */
function valueCovenantPortable (expectedHashOutputs: Buffer) {
  const script = new Script().add(Opcode.OP_DUP)
  pushTxCoreCompact(script)
  script.add(Opcode.OP_VERIFY)
  extractHashOutputsPortable(script)
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
  // NOT s.toBuffer('be', 32) — bn.js's native signature against a toBuffer
  // that crypto/bn REPLACES with an options-object form, so the length would
  // be ignored and the result natural-length.
  //
  // That truncation is UNREACHABLE here, and the reason is not obvious enough
  // to leave unwritten: z is filtered to a leading byte of 0x01..0x7f above,
  // so z is in [2^248, 2^255); adding Gx (~0.476 * 2^256) never wraps; and the
  // low-S check caps the result at n/2. s therefore always lands in a band
  // with a leading byte of 0x7a..0x7f and is always 32 bytes. Verified over
  // 62,000 candidates, none with a leading zero.
  //
  // An earlier note here claimed this produced an unspendable covenant about
  // one call in 256. That was wrong. The call is still fixed, because the
  // safety is an accident of two filters that have nothing to do with buffer
  // length — widen the MINIMALDATA range or drop low-S and it becomes
  // reachable, silently, where DER_PREFIX declares s to be exactly 32 bytes.
  const sBE = s.toBuffer({ size: 32 })
  return (sBE[0]! >= 0x01) ? sBE : null // s <= n/2 already guarantees sBE[0] <= 0x7f
}

/**
 * The compact gate's grind predicate: `s = e + 2^248`, i.e. `z` with `byte[0]` incremented.
 *
 * The condition is `z[0] <= 0x7e`, which keeps `(z[0] + 1)` positive, minimally encoded and
 * carry-free, plus low-S. Acceptance is 49.61% (127/256; measured 49.62% over 50,000 random
 * preimages) — roughly two tries, against the ~2% of `sFromPreimage`.
 *
 * The low-S check is correct-by-construction insurance that will never fire. The tail is real —
 * `n/2` sits 2^127.0 below 2^255, so an `s` with leading byte 0x7f (what `z[0] = 0x7e` gives)
 * CAN exceed `n/2` — but it is 2^127 wide inside a 2^248 band, so P(high-S | z[0] = 0x7e) =
 * 2^-121 and P(high-S) = 2^-129 overall. Measured: 0 rejections in 24,811 in-band samples. Keep
 * it; do not describe it as guarding anything observable.
 */
function sFromPreimageCompact (preimage: Buffer) {
  const z = Hash.sha256sha256(preimage)
  if (z[0]! > 0x7e) return null
  const s = Buffer.concat([Buffer.from([z[0]! + 1]), z.slice(1)])
  if (new BN(s).gt(HALF_N)) return null
  return s
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
    const pass = opts.form === 'compact' ? sFromPreimageCompact(preimage) : sFromPreimage(preimage)
    if (pass) return { preimage, tries: i + 1, field, nonce }
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
  A_SCALAR,
  COMPACT_PUBKEY,
  pushTxCoreCompact,
  authenticatorCompact,
  sFromPreimageCompact,
  extractHashOutputs,
  extractHashOutputsPortable,
  valueCovenantPortable,
  assertSighashAll,
  assertSighashType,
  SIGHASH_ALL_FORKID,
  SIGHASH_SINGLE_FORKID,
  SIGHASH_SINGLE_ANYONECANPAY_FORKID,
  SIGHASH_ALL_ANYONECANPAY_FORKID,
  hashOutputs,
  valueCovenant,
  valueCovenantSingle,
  sFromPreimage,
  grind
}
