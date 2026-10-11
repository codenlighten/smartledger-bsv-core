'use strict'

/* global describe, it, before, after */

// valueCovenantSingle: an output covenant under SIGHASH_SINGLE.
//
// Ported from @smartledger/bsv's test/smart_contract/single_output_covenant.js (9.28.0),
// where the helper originated. The case for a named helper — rather than leaving callers
// to compose it — is that the obvious composition is wrong: valueCovenant(hashOutputs([p]))
// with assertSighashType appended afterwards builds a lock that fails the HONEST spend,
// because pushTxCore consumes the preimage copy it checks and an assertion appended after
// the covenant body has nothing left to read. The last test pins that, because the ordering
// is the entire reason the helper exists.
//
// The hazard test is deliberate and asserted, not tolerated. Under SIGHASH_SINGLE the
// preimage commits to the output at the input's index and nothing else, so this covenant
// binds ONE output and leaves the rest free. That is what makes the flag useful for
// marketplace trades and what makes it wrong for binding where value goes. Asserting it
// means a future change to that behaviour has to come past this file.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const PrivateKey = bsv.PrivateKey
const Transaction = bsv.Transaction
const PushTx = bsv.Covenant.PushTx
const help = bsv.Covenant.Helpers
const Interpreter = bsv.Script.Interpreter

const SATS = 100000
const SINGLE = PushTx.SIGHASH_SINGLE_FORKID

describe('valueCovenantSingle (SIGHASH_SINGLE output covenant)', function () {
  this.timeout(20000)

  // OP_PUSH_TX needs post-Genesis limits: the preimage push exceeds the 520-byte
  // pre-Genesis element cap. The caps are PROCESS-WIDE statics, so raising them without
  // putting them back makes later files in the same mocha run answer a different
  // question — measured here, not guessed: leaving them raised turned two pre-Genesis
  // consensus fixtures (test/script/interpreter.js, test/script/shift_cost.js) into
  // false accepts. Save and restore around this file only.
  let savedLimits
  before(function () {
    savedLimits = Interpreter.getLimits()
    help.enableGenesis()
  })
  after(function () { Interpreter.setLimits(savedLimits) })

  const beneficiary = PrivateKey.fromRandom()
  const attacker = PrivateKey.fromRandom()

  function pinnedOutput () { return help.p2pkhOutput(beneficiary, SATS - 500) }

  // Returns the verify result for spending `lock` with `outputs` under `flag`.
  function spendWith (lock, outputs, flag) {
    const spend = help.fundAndSpend(lock, SATS, { outputs }).spend
    const g = PushTx.grind(spend, 0, lock, SATS, { sighashType: flag || SINGLE })
    spend.inputs[0].setScript(new Script().add(g.preimage))
    return help.verify(spend.inputs[0].script, lock, { tx: spend, satoshis: SATS })
  }

  it('accepts the honest spend that recreates the pinned output', function () {
    const pinned = pinnedOutput()
    spendWith(PushTx.valueCovenantSingle(pinned), [pinned]).ok.should.equal(true)
  })

  it('takes an Output or its digest, and builds the same lock either way', function () {
    const pinned = pinnedOutput()
    const fromOutput = PushTx.valueCovenantSingle(pinned)
    const fromDigest = PushTx.valueCovenantSingle(PushTx.hashOutputs([pinned]))
    fromOutput.toHex().should.equal(fromDigest.toHex())
    spendWith(fromDigest, [pinned]).ok.should.equal(true)
  })

  it('refuses a spend that puts someone else at the pinned index', function () {
    const pinned = pinnedOutput()
    spendWith(PushTx.valueCovenantSingle(pinned),
      [help.p2pkhOutput(attacker, SATS - 500)]).ok.should.equal(false)
  })

  it('pins the flag, so the lock cannot be spent under SIGHASH_ALL', function () {
    const pinned = pinnedOutput()
    spendWith(PushTx.valueCovenantSingle(pinned), [pinned],
      PushTx.SIGHASH_ALL_FORKID).ok.should.equal(false)
  })

  it('accepts the ANYONECANPAY variant, which also leaves sibling inputs open', function () {
    const pinned = pinnedOutput()
    const lock = PushTx.valueCovenantSingle(pinned,
      { sighashType: PushTx.SIGHASH_SINGLE_ANYONECANPAY_FORKID })
    spendWith(lock, [pinned], PushTx.SIGHASH_SINGLE_ANYONECANPAY_FORKID).ok.should.equal(true)
  })

  it('refuses to build a lock whose name would be a lie', function () {
    const pinned = pinnedOutput()
    ;(function () {
      PushTx.valueCovenantSingle(pinned, { sighashType: PushTx.SIGHASH_ALL_FORKID })
    }).should.throw(/needs SIGHASH_SINGLE\|FORKID/)
    ;(function () { PushTx.valueCovenantSingle(Buffer.alloc(31)) }).should.throw(/32-byte/)
    ;(function () { PushTx.valueCovenantSingle('deadbeef') }).should.throw(/32-byte/)
    ;(function () { PushTx.valueCovenantSingle() }).should.throw(/32-byte/)
  })

  it('accepts only the two legal SIGHASH_SINGLE words, not a mask match', function () {
    // The guard used to be `(sighashType & 0x1f) !== SIGHASH_SINGLE`, which let through
    // 0x03 (SINGLE without FORKID) and anything carrying stray high bits. Neither fails
    // loudly: pushTxCore's synthetic signature commits to the flag word, so the lock just
    // refuses the honest spend, at the same byte count.
    const pinned = pinnedOutput()
    PushTx.valueCovenantSingle(pinned, { sighashType: SINGLE })
      .toHex().should.equal(PushTx.valueCovenantSingle(pinned).toHex())
    ;[0x03, 0x83, 0x143, -1, 0, null, '0x43'].forEach(function (bad) {
      ;(function () {
        PushTx.valueCovenantSingle(pinned, { sighashType: bad })
      }).should.throw(/needs SIGHASH_SINGLE\|FORKID/, 'accepted sighashType ' + String(bad))
    })
  })

  it('refuses an object that merely has toBufferWriter', function () {
    ;(function () {
      PushTx.valueCovenantSingle({ toBufferWriter: function () {} })
    }).should.throw(/with script and satoshis/)
  })

  it('constrains ONE output and leaves the rest free — the documented hazard', function () {
    // Not a gap in the helper: it is what SIGHASH_SINGLE means. The preimage's hashOutputs
    // covers the output at the input's index alone, so a spender may append whatever they
    // like. A covenant pinning a 0-satoshi burn here would constrain the burn and leave
    // the asset's satoshis free to go anywhere. Use valueCovenant to bind every output.
    const pinned = pinnedOutput()
    const r = spendWith(PushTx.valueCovenantSingle(pinned),
      [pinned, help.p2pkhOutput(attacker, 1)])
    r.ok.should.equal(true)
  })

  it('refuses an all-zero pin, which would pin nothing while looking like it pins', function () {
    // Under SIGHASH_SINGLE, 32 zero bytes is not a digest: it is what BIP-143 puts in
    // hashOutputs when the input's index is out of range, i.e. there is no output there.
    // Measured before the guard existed: a lock pinned to zeros verified against a spend
    // with NO outputs at all. Caught by an outside review of the API, not by these tests.
    ;(function () { PushTx.valueCovenantSingle(Buffer.alloc(32)) }).should.throw(/all-zero pin/)
  })

  it('refuses an out-of-range index when a real output is pinned', function () {
    const pinned = pinnedOutput()
    const lock = PushTx.valueCovenantSingle(pinned)
    const spend = help.fundAndSpend(lock, SATS, { outputs: [] }).spend
    spend.outputs.length.should.equal(0)
    const g = PushTx.grind(spend, 0, lock, SATS, { sighashType: SINGLE })
    spend.inputs[0].setScript(new Script().add(g.preimage))
    help.verify(spend.inputs[0].script, lock, { tx: spend, satoshis: SATS })
      .ok.should.equal(false)
  })

  describe('it pins the output at the INPUT\'s index, not output 0', function () {
    // The covenant reads hashOutputs out of its own preimage, and under SIGHASH_SINGLE that
    // is the output sharing the spending input's index. Put the covenant at input 1 and the
    // pinned output has to be at output 1. Worth asserting because "pins one output" is
    // easy to read as "pins the first output".
    const other = PrivateKey.fromRandom()

    function spendAtIndexOne (lock, outputs) {
      const fundA = new Transaction().addOutput(new Transaction.Output({
        script: Script.buildPublicKeyHashOut(other.toAddress()), satoshis: 5000
      }))
      const fundB = new Transaction().addOutput(new Transaction.Output({
        script: lock, satoshis: SATS
      }))
      const spend = new Transaction()
      spend.addInput(new Transaction.Input({
        prevTxId: fundA.hash, outputIndex: 0, script: Script.empty()
      }), Script.buildPublicKeyHashOut(other.toAddress()), 5000)
      spend.addInput(new Transaction.Input({
        prevTxId: fundB.hash, outputIndex: 0, script: Script.empty()
      }), lock, SATS)
      outputs.forEach(function (o) { spend.addOutput(o) })
      const g = PushTx.grind(spend, 1, lock, SATS, { sighashType: SINGLE })
      spend.inputs[1].setScript(new Script().add(g.preimage))
      return help.verify(spend.inputs[1].script, lock,
        { tx: spend, inputIndex: 1, satoshis: SATS })
    }

    it('accepts the pinned output at index 1 when the input is index 1', function () {
      const pinned = pinnedOutput()
      spendAtIndexOne(PushTx.valueCovenantSingle(pinned),
        [help.p2pkhOutput(other, 4000), pinned]).ok.should.equal(true)
    })

    it('refuses the same output placed at index 0 instead', function () {
      const pinned = pinnedOutput()
      spendAtIndexOne(PushTx.valueCovenantSingle(pinned),
        [pinned, help.p2pkhOutput(other, 4000)]).ok.should.equal(false)
    })

    it('refuses when there is no output at the input\'s index', function () {
      const pinned = pinnedOutput()
      spendAtIndexOne(PushTx.valueCovenantSingle(pinned),
        [help.p2pkhOutput(other, 4000)]).ok.should.equal(false)
    })
  })

  it('exists because the obvious composition fails the honest spend', function () {
    // valueCovenant consumes the preimage to produce hashOutputs; appending the flag
    // assertion afterwards leaves it nothing to read, and the lock rejects the very spend
    // it was built for. Same byte count, so size is no clue that it is wrong.
    const pinned = pinnedOutput()
    const naive = PushTx.valueCovenant(PushTx.hashOutputs([pinned]))
    PushTx.assertSighashType(naive, SINGLE)
    spendWith(naive, [pinned]).ok.should.equal(false)
    naive.toBuffer().length.should.equal(PushTx.valueCovenantSingle(pinned).toBuffer().length)
  })
})
