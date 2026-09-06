'use strict'

/* global describe, it */
require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction

// Genesis restored OP_RETURN's original meaning: it terminates the script and the
// top stack item decides validity. This port only had the pre-Genesis rule, where
// OP_RETURN invalidates outright — a false REJECT of every post-Genesis script that
// uses it, and of the OP_FALSE OP_RETURN <data> pattern the network carries data in.
//
// Ported from @smartledger/bsv, where the two behaviours already agreed.
describe('OP_RETURN after Genesis', function () {
  const PRE = 0
  const POST = Interpreter.SCRIPT_UTXO_AFTER_GENESIS | Interpreter.SCRIPT_GENESIS

  function run (build, flags) {
    const lock = new Script()
    build(lock, Opcode)
    const i = new Interpreter()
    let ok
    try {
      ok = i.verify(new Script(), lock, new Transaction(), 0, flags)
    } catch (e) {
      return 'threw ' + e.message
    }
    return ok ? 'ACCEPT' : i.errstr
  }

  it('still invalidates the script before Genesis', function () {
    run(function (s, O) { s.add(O.OP_1).add(O.OP_RETURN) }, PRE)
      .should.equal('SCRIPT_ERR_OP_RETURN')
  })

  it('ends the script after Genesis, with the top item deciding', function () {
    run(function (s, O) { s.add(O.OP_1).add(O.OP_RETURN) }, POST).should.equal('ACCEPT')
    run(function (s, O) { s.add(O.OP_0).add(O.OP_RETURN) }, POST)
      .should.equal('SCRIPT_ERR_EVAL_FALSE_IN_STACK')
  })

  // The property that makes OP_FALSE OP_RETURN <data> safe to carry anything: what
  // follows a top-level OP_RETURN is never read, so it cannot make the script
  // invalid however malformed it is.
  it('does not read what follows, even an unbalanced conditional', function () {
    run(function (s, O) {
      s.add(O.OP_1).add(O.OP_RETURN).add(Buffer.from('arbitrary bytes')).add(O.OP_IF)
    }, POST).should.equal('ACCEPT')
  })

  // Inside a conditional it is weaker: execution is suppressed, but the conditional
  // grammar is still checked to the end of the script. This is the distinction
  // `nonTopLevelReturnAfterGenesis` carries, and getting it wrong in either
  // direction changes what the network accepts.
  it('inside a conditional, suppresses execution but keeps checking grammar', function () {
    run(function (s, O) {
      s.add(O.OP_1).add(O.OP_IF).add(O.OP_RETURN).add(O.OP_ENDIF).add(O.OP_1)
    }, POST).should.equal('SCRIPT_ERR_EVAL_FALSE_NO_RESULT')

    run(function (s, O) {
      s.add(O.OP_1).add(O.OP_IF).add(O.OP_RETURN)
    }, POST).should.equal('SCRIPT_ERR_UNBALANCED_CONDITIONAL')
  })

  it('resets the flags between evaluations', function () {
    const i = new Interpreter()
    i.set({ flags: POST, script: new Script().add(Opcode.OP_1).add(Opcode.OP_RETURN), tx: new Transaction(), nin: 0 })
    i.evaluate().should.equal(true)
    i.returned.should.equal(true)
    i.initialize()
    i.returned.should.equal(false)
    i.nonTopLevelReturnAfterGenesis.should.equal(false)
  })
})
