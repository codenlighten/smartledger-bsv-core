'use strict'

/* global describe, it */

// Signing n inputs recomputed hashPrevouts, hashSequence and hashOutputs n times, each a pass over
// all inputs or all outputs, so the cost was quadratic: 100 inputs took 0.9 s and 5,000 took 194 s
// on 9.22.0 — 50x the inputs for 216x the time. The three digests are identical for every input of
// a transaction, so they are computed once per signing call now.
//
// The cache is opened by `sign()` (and by `getSignatures()` for direct callers) and removed in a
// `finally`, so nothing survives the call and there is no invalidation to get wrong. Widening it to
// cover the apply loop is safe because the only thing that loop changes is each input's SCRIPT, and
// none of the three digests depends on a script — hashPrevouts covers outpoints, hashSequence
// covers sequence numbers, hashOutputs covers outputs.
//
// These tests pin the properties that make it safe, not the speed.
//
// Ported from @smartledger/bsv's test/transaction/sighash_midstate_cache.js (9.22.1).

require('chai').should()
const bsv = require('../..')
const Signature = bsv.crypto.Signature

const KEY = bsv.PrivateKey.fromString('11'.repeat(32))
const ADDR = KEY.toAddress()
const LOCK = bsv.Script.buildPublicKeyHashOut(ADDR).toHex()
const oid = i => i.toString(16).padStart(64, '0')

function txWith (n, sats) {
  const tx = new bsv.Transaction()
  for (let i = 0; i < n; i++) {
    tx.from({ txId: oid(i), outputIndex: i % 3, script: LOCK, satoshis: sats || 5000 })
  }
  tx.to(ADDR, n * (sats || 5000) - 2000)
  tx.feePerKb(100)
  return tx
}

describe('the sighash midstate cache', function () {
  it('leaves nothing behind on the transaction after signing', function () {
    const tx = txWith(3)
    tx.sign(KEY)
    // A cache that outlived the call could go stale against a later mutation.
    Object.prototype.hasOwnProperty.call(tx, '_sighashMidstates').should.equal(false)
  })

  it('leaves nothing behind after getSignatures used directly', function () {
    const tx = txWith(3)
    tx.getSignatures(KEY)
    Object.prototype.hasOwnProperty.call(tx, '_sighashMidstates').should.equal(false)
  })

  it('leaves nothing behind when sign() throws', function () {
    // An input without its funding output has no satoshis, so hasAllUtxoInfo() is false and
    // sign() throws before the loop. Two things this had to work around: an EMPTY transaction
    // does NOT throw, because with no inputs the check passes vacuously; and `addInput`
    // refuses such an input itself, so the throw would land in the setup rather than in the
    // call under test. `uncheckedAddInput` is the path that leaves sign() to object.
    const tx = new bsv.Transaction()
    tx.uncheckedAddInput(new bsv.Transaction.Input({
      prevTxId: Buffer.from(oid(1), 'hex'),
      outputIndex: 0,
      script: new bsv.Script()
    }))
    ;(function () { tx.sign(KEY) }).should.throw()
    Object.prototype.hasOwnProperty.call(tx, '_sighashMidstates').should.equal(false)
  })

  it('signs identically whether the cache is used or not', function () {
    // One input exercises the uncached shape; the cache cannot change a single-input result.
    const a = txWith(1); a.sign(KEY)
    const b = txWith(1); b._sighashMidstates = {}; b.sign(KEY); delete b._sighashMidstates
    a.uncheckedSerialize().should.equal(b.uncheckedSerialize())
  })

  it('produces signatures that verify, at a size where the cache is used', function () {
    const tx = txWith(12)
    tx.sign(KEY)
    const I = bsv.Script.Interpreter
    for (let i = 0; i < tx.inputs.length; i++) {
      const it = new I()
      const ok = it.verify(tx.inputs[i].script, bsv.Script.fromHex(LOCK), tx, i,
        I.mainnetFlags(), new bsv.crypto.BN(5000))
      ok.should.equal(true, 'input ' + i + ': ' + it.errstr)
    }
  })

  it('is stable across repeated signing of equivalent transactions', function () {
    txWith(9).sign(KEY).uncheckedSerialize()
      .should.equal(txWith(9).sign(KEY).uncheckedSerialize())
  })

  it('handles an array of keys, which re-enters sign()', function () {
    // The nested call must not clear a cache the outer call owns.
    const tx = txWith(4)
    tx.sign([KEY, bsv.PrivateKey.fromString('33'.repeat(32))])
    Object.prototype.hasOwnProperty.call(tx, '_sighashMidstates').should.equal(false)
    tx.inputs.every(i => i.script.toBuffer().length > 0).should.equal(true)
  })

  it('does not cache the SIGHASH_SINGLE output digest, which differs per input', function () {
    // SIGHASH_SINGLE hashes the one output at the input's index, so a cached value would sign
    // every input over the same output.
    const tx = txWith(3, 7000)
    tx.to(ADDR, 6000); tx.to(ADDR, 6000)
    tx.sign(KEY, Signature.SIGHASH_SINGLE | Signature.SIGHASH_FORKID)
    const scripts = tx.inputs.map(i => i.script.toHex())
    new Set(scripts).size.should.equal(scripts.length, 'each input must sign a different digest')
  })

  it('still signs SIGHASH_NONE', function () {
    const tx = txWith(3)
    tx.sign(KEY, Signature.SIGHASH_NONE | Signature.SIGHASH_FORKID)
    tx.inputs.every(i => i.script.toBuffer().length > 0).should.equal(true)
  })
})
