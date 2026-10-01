'use strict'

/* global describe, it */

// Two classes of false reject found by a differential fuzzer against @smartledger/bsv, both
// invisible to the node's 1483-row corpus and both live in published 1.0.0 through 1.0.2.
//
// 1. FOUR decode sites kept the 4-byte script-number default after Genesis. In the node every
//    operand decode takes params.MaxScriptNumLength(); only nLockTime and nSequence (5 bytes)
//    and the two CHECKMULTISIG counts (4 bytes) are era-independent. That list of three
//    exceptions is the whole rule, and it is worth stating because a sibling audit proposed
//    changing the multisig counts too — which would have made this package MORE permissive than
//    the node, a false accept.
//
// 2. CLTV and CSV were still enforced after Genesis. Genesis reverted both to upgradable NOPs
//    for outputs created after it, so the node reads
//      if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) || utxo_after_genesis) { ... }
//    and DISCOURAGE_UPGRADABLE_NOPS still fires inside that branch.

require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const BN = bsv.crypto.BN

const PRE = Interpreter.SCRIPT_VERIFY_P2SH
const POST = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_GENESIS |
  Interpreter.SCRIPT_UTXO_AFTER_GENESIS

function run (unlockAsm, lockAsm, flags) {
  const interp = new Interpreter()
  const ok = interp.verify(Script.fromASM(unlockAsm), Script.fromASM(lockAsm),
    new bsv.Transaction(), 0, flags, new BN(0))
  return ok ? 'OK' : interp.errstr.replace(/^SCRIPT_ERR_/, '')
}

// A non-minimal 5-byte encoding of 1.
const FIVE_BYTE_ONE = '0100000000'

describe('script numbers take the era\'s length after Genesis', function () {
  it('OP_ABS and the rest of its family', function () {
    run(FIVE_BYTE_ONE, 'OP_ABS OP_1 OP_EQUAL', POST).should.equal('OK')
    run(FIVE_BYTE_ONE, 'OP_1ADD OP_2 OP_EQUAL', POST).should.equal('OK')
    run(FIVE_BYTE_ONE, 'OP_NEGATE OP_1NEGATE OP_EQUAL', POST).should.equal('OK')
  })

  it('OP_SPLIT\'s position', function () {
    run('0102030405060708 ' + FIVE_BYTE_ONE, 'OP_SPLIT OP_DROP 01 OP_EQUAL', POST)
      .should.equal('OK')
  })

  it('OP_PICK and OP_ROLL\'s index', function () {
    run('aa bb ' + FIVE_BYTE_ONE, 'OP_PICK aa OP_EQUAL', POST).should.equal('OK')
  })

  it('and still refuses them before Genesis, where the limit is four', function () {
    run(FIVE_BYTE_ONE, 'OP_ABS', PRE).should.equal('SCRIPTNUM_OVERFLOW')
    run('0102030405060708 ' + FIVE_BYTE_ONE, 'OP_SPLIT', PRE).should.equal('SCRIPTNUM_OVERFLOW')
  })

  it('keeps OP_CHECKMULTISIG\'s counts at four bytes in EVERY era', function () {
    // The exception that a sibling audit nearly removed. Making these era-dependent would
    // accept a count the node refuses as SCRIPTNUM_OVERFLOW — the false-accept direction.
    const pub = bsv.PrivateKey.fromBuffer(Buffer.alloc(32, 0x44)).toPublicKey().toBuffer()
    const chronicle = POST | Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE
    ;[PRE, POST, chronicle].forEach(function (flags) {
      const sc = new Script().add('OP_0').add('OP_0').add(pub)
        .add(Buffer.from(FIVE_BYTE_ONE, 'hex')).add('OP_CHECKMULTISIG')
      const interp = new Interpreter()
      interp.verify(new Script(), sc, new bsv.Transaction(), 0, flags, new BN(0))
      interp.errstr.should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })
  })
})

describe('CLTV and CSV are upgradable NOPs after Genesis', function () {
  const CLTV = Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
  const CSV = Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY

  it('enforces neither after Genesis', function () {
    run('OP_1', 'OP_NOP2', POST | CLTV).should.equal('OK')
    run('OP_1', 'OP_NOP3', POST | CSV).should.equal('OK')
  })

  it('still enforces both before Genesis', function () {
    run('OP_1', 'OP_NOP2', PRE | CLTV).should.equal('UNSATISFIED_LOCKTIME')
    run('OP_1', 'OP_NOP3', PRE | CSV).should.equal('UNSATISFIED_LOCKTIME')
  })

  it('still discourages them as NOPs when the caller asks', function () {
    // The check stays INSIDE the not-enabled branch: treating the opcode as a NOP is not the
    // same as ignoring it. Dropping this would trade a false reject for a missing check.
    const d = Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    run('OP_1', 'OP_NOP2', POST | CLTV | d).should.equal('DISCOURAGE_UPGRADABLE_NOPS')
    run('OP_1', 'OP_NOP3', POST | CSV | d).should.equal('DISCOURAGE_UPGRADABLE_NOPS')
  })
})
