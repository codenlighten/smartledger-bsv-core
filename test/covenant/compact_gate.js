'use strict'

/* global describe, it, before, after */

// The compact gate and the portable covenant in core, cross-checked against the derivation
// rather than against the other package's constants.
//
// The point of this file is NOT that core agrees with @smartledger/bsv — two transliterations
// of one mistake agree perfectly. It is that:
//
//   1. A_SCALAR is DERIVED here from 2^248 * Gx^-1 mod n, by modular inversion, and compared
//      with the shipped constant. A typo in the constant fails the suite instead of shipping a
//      gate nobody can spend.
//   2. COMPACT_PUBKEY is recomputed as a*G, so the embedded key is verified rather than trusted.
//   3. The gate's defining identity Gx * a == 2^248 (mod n) is checked directly.
//   4. The emitted bytes are compared with the OTHER package, which is only meaningful because
//      1-3 establish the bytes are right in the first place.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const BN = bsv.crypto.BN
const P = bsv.Covenant.PushTx
const H = bsv.Covenant.Helpers
const I = bsv.Script.Interpreter

const N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
const SATS = 50000
const FEE = 500
const PRE_GENESIS_LIMITS = {
  maxScriptElementSize: 520, maxScriptSize: 10000, maxOpsPerScript: 500, maxScriptNumLength: 4
}

function outputFor (seed, sats) {
  const k = bsv.PrivateKey.fromBuffer(Buffer.from(seed.repeat(32), 'hex'))
  return new bsv.Transaction.Output({
    script: bsv.Script.buildPublicKeyHashOut(k.toAddress()), satoshis: sats
  })
}

describe('the compact OP_PUSH_TX gate (core)', function () {
  this.timeout(30000)

  it('derives A_SCALAR independently: a = 2^248 * Gx^-1 mod n', function () {
    const Gx = new BN(P.Gx)
    const derived = new BN(2).pow(new BN(248)).mul(Gx.invm(N)).mod(N)
    derived.toString(16).should.equal(P.A_SCALAR.toString(16),
      'the shipped constant must equal the modular derivation, not merely look like it')
  })

  it('satisfies the identity the whole gate rests on: Gx * a == 2^248 (mod n)', function () {
    const lhs = new BN(P.Gx).mul(P.A_SCALAR).mod(N)
    lhs.toString(16).should.equal(new BN(2).pow(new BN(248)).toString(16))
  })

  it('recomputes COMPACT_PUBKEY as a*G rather than trusting it', function () {
    const Q = bsv.PublicKey.fromPoint(bsv.crypto.Point.getG().mul(P.A_SCALAR), true)
    Q.toBuffer().toString('hex').should.equal(P.COMPACT_PUBKEY.toString('hex'))
  })

  it('is 89 bytes against the classic 377, and emits the expected opcodes', function () {
    P.authenticatorCompact().toBuffer().length.should.equal(89)
    P.authenticator().toBuffer().length.should.equal(377)
    P.authenticatorCompact().toASM().should.match(
      /^OP_HASH256 OP_1 OP_SPLIT OP_SWAP OP_BIN2NUM OP_1ADD OP_1 OP_NUM2BIN OP_SWAP OP_CAT /)
  })

  it('contains exactly one CHECKSIG-family opcode (defence in depth, not the proof)', function () {
    // The real guard is that the bytes equal the published gate. This catches the crudest edit:
    // a spend path checking a SPENDER signature against a key whose private half is published.
    const buf = P.authenticatorCompact().toBuffer()
    let n = 0
    let i = 0
    while (i < buf.length) {
      const op = buf[i]
      if (op >= 0x01 && op <= 0x4b) { i += 1 + op; continue }
      if (op >= 0xac && op <= 0xaf) n++
      i++
    }
    n.should.equal(1)
  })

  it('matches @smartledger/bsv byte for byte (meaningful only given the checks above)', function () {
    let other
    try { other = require('@smartledger/bsv') } catch (e) { this.skip(); return }
    const O = other.SmartContract.PushTx
    P.authenticatorCompact().toHex().should.equal(O.authenticatorCompact().toHex())
    P.A_SCALAR.toString(16).should.equal(O.A_SCALAR.toString(16))
    P.COMPACT_PUBKEY.toString('hex').should.equal(O.COMPACT_PUBKEY.toString('hex'))
    P.extractHashOutputsPortable(new Script()).toHex()
      .should.equal(O.extractHashOutputsPortable(new other.Script()).toHex())
    const out = outputFor('88', SATS - FEE)
    P.valueCovenantPortable(P.hashOutputs([out])).toHex()
      .should.equal(O.valueCovenantPortable(O.hashOutputs([out])).toHex())
  })

  describe('the portable covenant', function () {
    let saved
    before(function () { saved = I.getLimits(); I.useGenesisLimits() })
    after(function () { I.setLimits(saved) })

    it('has no Chronicle-gated opcode in it', function () {
      const buf = P.valueCovenantPortable(P.hashOutputs([outputFor('88', SATS - FEE)])).toBuffer()
      let i = 0
      const gated = []
      while (i < buf.length) {
        const op = buf[i]
        if (op >= 0x01 && op <= 0x4b) { i += 1 + op; continue }
        if (op === 0xb3 || op === 0xb4 || op === 0xb5) gated.push(op)
        i++
      }
      gated.should.deep.equal([])
      buf.length.should.equal(135)
    })

    it('verifies pre-GENESIS and pre-Chronicle, with a control proving the caps were live',
      function () {
        const out = outputFor('88', SATS - FEE)
        const lock = P.valueCovenantPortable(P.hashOutputs([out]))
        const spend = H.fundAndSpend(lock, SATS, { outputs: [out] }).spend
        P.grind(spend, 0, lock, SATS, { form: 'compact' })
        const pre = H.rawPreimage(spend, 0, lock, SATS)
        pre.length.should.equal(292)
        spend.inputs[0].setScript(new Script().add(Buffer.from(pre)))

        const flags = I.mainnetFlags() & ~(I.SCRIPT_UTXO_AFTER_GENESIS | I.SCRIPT_GENESIS |
          I.SCRIPT_UTXO_AFTER_CHRONICLE | I.SCRIPT_ENABLE_CHRONICLE)
        const genesisLimits = I.getLimits()
        I.setLimits(PRE_GENESIS_LIMITS)
        try {
          const interp = new I()
          interp.verify(spend.inputs[0].script, lock, spend, 0, flags, new BN(SATS))
            .should.equal(true, 'verdict was ' + (interp.errstr || 'accept'))
          const ctrl = new I()
          ctrl.verify(new Script(),
            Script.fromHex('4d' + '1802' + 'aa'.repeat(536) + '51'), spend, 0, flags, new BN(SATS))
          ctrl.errstr.should.equal('SCRIPT_ERR_PUSH_SIZE')
        } finally { I.setLimits(genesisLimits) }
      })

    it('refuses a different output set', function () {
      const out = outputFor('88', SATS - FEE)
      const lock = P.valueCovenantPortable(P.hashOutputs([out]))
      const evil = H.fundAndSpend(lock, SATS, { outputs: [outputFor('89', SATS - FEE)] }).spend
      P.grind(evil, 0, lock, SATS, { form: 'compact' })
      evil.inputs[0].setScript(new Script().add(Buffer.from(H.rawPreimage(evil, 0, lock, SATS))))
      H.verify(evil.inputs[0].script, lock, { tx: evil, satoshis: SATS }).ok.should.equal(false)
    })
  })

  it('grind defaults to the classic predicate, so no existing caller changes', function () {
    const lock = P.authenticator()
    const out = outputFor('91', 49500)
    const saved = I.getLimits()
    I.useGenesisLimits()
    try {
      const spend = H.fundAndSpend(lock, SATS, { outputs: [out] }).spend
      P.grind(spend, 0, lock, SATS)
      const pre = H.rawPreimage(spend, 0, lock, SATS)
      ;(!!P.sFromPreimage(pre)).should.equal(true, 'default must satisfy the CLASSIC predicate')
    } finally { I.setLimits(saved) }
  })
})
