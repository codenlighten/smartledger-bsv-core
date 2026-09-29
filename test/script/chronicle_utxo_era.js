'use strict'

/* global describe, it */

// Chronicle-restored opcodes gate on the era of the OUTPUT BEING SPENT, which the node
// calls utxo_after_chronicle — never on this library's SCRIPT_ENABLE_CHRONICLE opt-in.
//
// Gating on the opt-in was a silent wrong answer rather than an error. Under the node's own
// flag sets, which set UTXO_AFTER_CHRONICLE, OP_LEFT, OP_RIGHT, OP_SUBSTR, OP_VER,
// OP_LSHIFTNUM and OP_RSHIFTNUM were treated as upgradable NOPs: they consumed nothing, the
// script ran on, and an out-of-range argument that the node rejects produced no error at
// all. That cost 7 false accepts and several false rejects across the node's corpus.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = bsv.Script.Interpreter

// The node's shape: the UTXO is post-Chronicle, without this library's opt-in bit.
const UTXO_ERA = Interpreter.SCRIPT_VERIFY_P2SH |
  Interpreter.SCRIPT_UTXO_AFTER_GENESIS |
  Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE
const PRE_CHRONICLE = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_UTXO_AFTER_GENESIS

function run (asm, flags) {
  const interp = new Interpreter()
  const ok = interp.verify(new Script(), Script.fromASM(asm), new bsv.Transaction(), 0,
    flags, new bsv.crypto.BN(0))
  return { ok, errstr: interp.errstr, stack: interp.stack.map(b => b.toString('hex')) }
}

describe('Chronicle opcodes follow the UTXO era, not the opt-in flag', function () {
  it('runs OP_LEFT when the UTXO is post-Chronicle', function () {
    const r = run('aabbcc OP_2 OP_LEFT aabb OP_EQUAL', UTXO_ERA)
    r.ok.should.equal(true, r.errstr)
  })

  it('runs OP_RIGHT and OP_SUBSTR the same way', function () {
    run('aabbcc OP_2 OP_RIGHT bbcc OP_EQUAL', UTXO_ERA).ok.should.equal(true)
    run('aabbcc OP_1 OP_1 OP_SUBSTR bb OP_EQUAL', UTXO_ERA).ok.should.equal(true)
  })

  // The false-accept class: an out-of-range argument has to be an error, not a no-op.
  it('refuses a length past the end instead of doing nothing', function () {
    run('aabbcc OP_5 OP_LEFT', UTXO_ERA).errstr.should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
    run('aabbcc OP_5 OP_RIGHT', UTXO_ERA).errstr.should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
    run('aabbcc OP_3 OP_1 OP_SUBSTR', UTXO_ERA).errstr.should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
  })

  it('refuses too few stack items instead of doing nothing', function () {
    run('OP_2 OP_LEFT', UTXO_ERA).errstr.should.equal('SCRIPT_ERR_INVALID_STACK_OPERATION')
    run('aabbcc OP_1 OP_SUBSTR', UTXO_ERA).errstr.should.equal('SCRIPT_ERR_INVALID_STACK_OPERATION')
  })

  it('is still an upgradable NOP before Chronicle, consuming nothing', function () {
    // The bytes were OP_NOP4/5/6, so the network does nothing with them. The operands
    // stay on the stack, which is what tells a NOP apart from a consuming opcode.
    const r = run('aabbcc OP_2 OP_LEFT', PRE_CHRONICLE)
    r.stack.should.deep.equal(['aabbcc', '02'])
  })

  it('and is discouraged before Chronicle when the caller asks', function () {
    const flags = PRE_CHRONICLE | Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
    run('aabbcc OP_2 OP_LEFT OP_1', flags).errstr
      .should.equal('SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS')
  })

  it('accepts the opt-in flag as well, since both mean Chronicle applies', function () {
    const optIn = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_UTXO_AFTER_GENESIS |
      Interpreter.SCRIPT_ENABLE_CHRONICLE
    run('aabbcc OP_2 OP_LEFT aabb OP_EQUAL', optIn).ok.should.equal(true)
  })
})
