'use strict'

/* global describe, it */

// verify() is a transcription of the node's VerifyScript, and four of its conditions had
// been flattened into flag tests that ignore which era the output being spent belongs to.
// Each block below pins one of them, with the rule it comes from.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = bsv.Script.Interpreter
const Hash = bsv.crypto.Hash

const P2SH = Interpreter.SCRIPT_VERIFY_P2SH
const GENESIS = Interpreter.SCRIPT_GENESIS
const UTXO_AFTER_GENESIS = Interpreter.SCRIPT_UTXO_AFTER_GENESIS
const UTXO_AFTER_CHRONICLE = Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE
const CHRONICLE = Interpreter.SCRIPT_CHRONICLE
const CLEANSTACK = Interpreter.SCRIPT_VERIFY_CLEANSTACK
const SIGPUSHONLY = Interpreter.SCRIPT_VERIFY_SIGPUSHONLY

function run (sigAsm, pubkeyAsm, flags, version) {
  const tx = new bsv.Transaction()
  if (version !== undefined) tx.version = version
  const interp = new Interpreter()
  const ok = interp.verify(Script.fromASM(sigAsm), Script.fromASM(pubkeyAsm), tx, 0, flags,
    new bsv.crypto.BN(0))
  return { ok, errstr: interp.errstr }
}

// A redeem script that succeeds on its own, and the P2SH output that commits to it.
const REDEEM = Script.fromASM('OP_1')
const REDEEM_HEX = REDEEM.toBuffer().toString('hex')
const P2SH_OUT = 'OP_HASH160 ' + Hash.sha256ripemd160(REDEEM.toBuffer()).toString('hex') +
  ' OP_EQUAL'

// A redeem script that FAILS. Before Genesis this makes the spend invalid; after Genesis the
// redeem script is never run, so the same spend is valid — which is the whole distinction.
const BAD_REDEEM = Script.fromASM('OP_0')
const BAD_REDEEM_HEX = BAD_REDEEM.toBuffer().toString('hex')
const BAD_P2SH_OUT = 'OP_HASH160 ' + Hash.sha256ripemd160(BAD_REDEEM.toBuffer()).toString('hex') +
  ' OP_EQUAL'

describe('verify() follows the era of the output being spent', function () {
  describe('Genesis removed P2SH', function () {
    it('runs the redeem script when the output predates Genesis', function () {
      run(REDEEM_HEX, P2SH_OUT, P2SH).ok.should.equal(true)
    })

    it('refuses a redeem script that fails, before Genesis', function () {
      const r = run(BAD_REDEEM_HEX, BAD_P2SH_OUT, P2SH)
      r.ok.should.equal(false)
      r.errstr.should.equal('SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK')
    })

    // The 14 false rejects. After Genesis a P2SH-shaped output is an ordinary script: the
    // hash-and-equal is the whole check and what the push happens to contain is not code.
    it('accepts that same spend after Genesis, where the redeem script is not code', function () {
      run(BAD_REDEEM_HEX, BAD_P2SH_OUT, P2SH | GENESIS | UTXO_AFTER_GENESIS).ok
        .should.equal(true)
    })

    it('and does not demand a push-only scriptSig for one after Genesis', function () {
      // OP_NOP before the push is not a push. Pre-Genesis P2SH refuses it by name.
      run('OP_NOP ' + REDEEM_HEX, P2SH_OUT, P2SH).errstr
        .should.equal('SCRIPT_ERR_SIG_PUSHONLY')
      run('OP_NOP ' + REDEEM_HEX, P2SH_OUT, P2SH | GENESIS | UTXO_AFTER_GENESIS).ok
        .should.equal(true)
    })
  })

  describe('a UTXO cannot be post-Chronicle without being post-Genesis', function () {
    it('names the flag set rather than guessing an era', function () {
      const r = run('OP_1', 'OP_1', P2SH | UTXO_AFTER_CHRONICLE)
      r.ok.should.equal(false)
      r.errstr.should.equal('SCRIPT_ERR_INVALID_FLAGS')
    })

    it('accepts the pair together', function () {
      run('OP_1', 'OP_1', P2SH | UTXO_AFTER_GENESIS | UTXO_AFTER_CHRONICLE).ok
        .should.equal(true)
    })
  })

  describe('CLEANSTACK', function () {
    it('judges the stack the last evaluation left, not a copy taken before it', function () {
      // Two items reach the scriptPubkey and one is consumed, so the working stack ends at
      // one item and the spend is clean. Comparing the pre-scriptPubkey copy saw two.
      run('OP_1 OP_1', 'OP_ADD', P2SH | CLEANSTACK).ok.should.equal(true)
      run('OP_1 OP_1', 'OP_NOP', P2SH | CLEANSTACK).errstr.should.equal('SCRIPT_ERR_CLEANSTACK')
    })

    it('still judges the redeem script\'s stack where P2SH ran', function () {
      run(REDEEM_HEX, P2SH_OUT, P2SH | CLEANSTACK).ok.should.equal(true)
      const twoLeft = Script.fromASM('OP_1 OP_1')
      const out = 'OP_HASH160 ' + Hash.sha256ripemd160(twoLeft.toBuffer()).toString('hex') +
        ' OP_EQUAL'
      run(twoLeft.toBuffer().toString('hex'), out, P2SH | CLEANSTACK).errstr
        .should.equal('SCRIPT_ERR_CLEANSTACK')
    })

    // The node reports a caller's bad flags; we used to throw, which turned a verdict into
    // a crash for anyone verifying with CLEANSTACK and no P2SH.
    it('reports CLEANSTACK without P2SH instead of throwing', function () {
      const r = run('OP_1', 'OP_1', CLEANSTACK)
      r.ok.should.equal(false)
      r.errstr.should.equal('SCRIPT_ERR_INVALID_FLAGS')
    })

    // Clean stack was only ever policy, so Chronicle ties it to the transaction version.
    it('is not applied to a malleable transaction version under Chronicle', function () {
      const flags = P2SH | CLEANSTACK | GENESIS | UTXO_AFTER_GENESIS | CHRONICLE |
        UTXO_AFTER_CHRONICLE
      run('OP_1 OP_1', 'OP_NOP', flags, 1).errstr.should.equal('SCRIPT_ERR_CLEANSTACK')
      run('OP_1 OP_1', 'OP_NOP', flags, 2).ok.should.equal(true)
    })
  })

  describe('SIGPUSHONLY is a rule of an era, not of the flag alone', function () {
    // The node's own corpus states both halves on one script: with GENESIS it expects
    // SIG_PUSHONLY, with the flag alone it expects OK.
    it('is not applied before Genesis', function () {
      run('OP_1 OP_NOP', 'OP_NOP', P2SH | SIGPUSHONLY).ok.should.equal(true)
    })

    it('is applied after Genesis', function () {
      run('OP_1 OP_NOP', 'OP_NOP', P2SH | SIGPUSHONLY | GENESIS | UTXO_AFTER_GENESIS).errstr
        .should.equal('SCRIPT_ERR_SIG_PUSHONLY')
    })

    it('under Chronicle, follows the transaction version', function () {
      const flags = P2SH | SIGPUSHONLY | GENESIS | UTXO_AFTER_GENESIS | CHRONICLE |
        UTXO_AFTER_CHRONICLE
      run('OP_1 OP_NOP', 'OP_NOP', flags, 1).errstr.should.equal('SCRIPT_ERR_SIG_PUSHONLY')
      run('OP_1 OP_NOP', 'OP_NOP', flags, 2).ok.should.equal(true)
    })
  })
})
