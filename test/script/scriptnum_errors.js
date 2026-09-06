'use strict'

/* global describe, it */
require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction

// Script number decoding fails for two consensus reasons, and the node names both
// in its script vectors: SCRIPT_ERR_SCRIPTNUM_OVERFLOW and
// SCRIPT_ERR_SCRIPTNUM_MINENCODE. Both used to arrive at the evaluator's catch as a
// bare Error and be flattened into SCRIPT_ERR_UNKNOWN_ERROR.
//
// The script failed either way, so nothing comparing ACCEPT against REJECT could see
// it — only a run comparing error CODES. It surfaced as a cross-repo divergence
// against @smartledger/bsv, which normalises them.
describe('script-number errors carry the node result code', function () {
  const MONOLITH = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC |
    Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES | Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES

  function run (build, flags) {
    const lock = new Script()
    build(lock, Opcode)
    const i = new Interpreter()
    const ok = i.verify(new Script(), lock, new Transaction(), 0, flags)
    return ok ? '(accepted)' : i.errstr
  }

  it('reports an overflow as SCRIPTNUM_OVERFLOW, not UNKNOWN_ERROR', function () {
    // A 5-byte operand is an overflow under the pre-Genesis 4-byte width.
    run(function (s, O) {
      s.add(Buffer.from('1234567890', 'hex')).add(Buffer.from([2])).add(O.OP_MUL)
    }, MONOLITH).should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
  })

  it('reports a non-minimal operand as SCRIPTNUM_MINENCODE', function () {
    // OP_NUM2BIN produces 0x0500 — two bytes where one would do, so it is a valid
    // stack element but not a minimally encoded script NUMBER. MINIMALDATA rejects
    // a non-minimal PUSH, which is a different rule and a different code, so the
    // value has to be computed rather than pushed to reach this one.
    run(function (s, O) {
      s.add(O.OP_5).add(O.OP_2).add(O.OP_NUM2BIN).add(O.OP_1).add(O.OP_ADD)
    }, MONOLITH | Interpreter.SCRIPT_VERIFY_MINIMALDATA)
      .should.equal('SCRIPT_ERR_SCRIPTNUM_MINENCODE')
  })

  it('still reports a genuinely unknown throw as UNKNOWN_ERROR', function () {
    // The fallback has to survive: an error with no scriptErr is unknown to the
    // interpreter and must not be given a code it does not have.
    const i = new Interpreter()
    i.set({ flags: 0, script: new Script().add(Opcode.OP_1), tx: new Transaction(), nin: 0 })
    const original = i.step
    i.step = function () { throw new Error('something the interpreter does not model') }
    i.evaluate().should.equal(false)
    i.errstr.should.match(/^SCRIPT_ERR_UNKNOWN_ERROR: /)
    i.step = original
  })
})
