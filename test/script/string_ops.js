'use strict'

/* global describe, it */
require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction

// OP_SUBSTR / OP_LEFT / OP_RIGHT — re-enabled BSV (Chronicle) string opcodes,
// original Satoshi semantics. Declared in the opcode map at 0xb3/0xb4/0xb5 but
// previously unimplemented (BAD_OPCODE). These tests verify behavior end-to-end.
describe('String opcodes OP_SUBSTR / OP_LEFT / OP_RIGHT', function () {
  const DATA = Buffer.from('aabbccdd', 'hex')

  // Build `<DATA> <ops...>` and assert the top of stack equals `expected`.
  function yields (buildOps, expectedHex) {
    const lock = new Script().add(DATA)
    buildOps(lock)
    lock.add(Buffer.from(expectedHex, 'hex')).add(Opcode.OP_EQUAL)
    const interp = new Interpreter()
    return interp.verify(new Script(), lock, new Transaction(), 0, 0)
  }
  function errors (buildOps) {
    const lock = new Script().add(DATA)
    buildOps(lock)
    const interp = new Interpreter()
    let ok
    try { ok = interp.verify(new Script(), lock, new Transaction(), 0, 0) } catch (e) { ok = false }
    return ok === false
  }

  it('OP_LEFT keeps the first n bytes', function () {
    yields(function (s) { s.add(Opcode.OP_2).add(Opcode.OP_LEFT) }, 'aabb').should.equal(true)
  })

  it('OP_RIGHT keeps the last n bytes', function () {
    yields(function (s) { s.add(Opcode.OP_2).add(Opcode.OP_RIGHT) }, 'ccdd').should.equal(true)
  })

  it('OP_RIGHT 0 yields the empty string (not the whole string)', function () {
    yields(function (s) { s.add(Opcode.OP_0).add(Opcode.OP_RIGHT) }, '').should.equal(true)
  })

  it('OP_LEFT 0 yields the empty string', function () {
    yields(function (s) { s.add(Opcode.OP_0).add(Opcode.OP_LEFT) }, '').should.equal(true)
  })

  it('OP_SUBSTR extracts in[begin : begin+size]', function () {
    // begin=1 size=2 -> bbcc.  Stack order is (in begin size -- out).
    yields(function (s) { s.add(Opcode.OP_1).add(Opcode.OP_2).add(Opcode.OP_SUBSTR) }, 'bbcc').should.equal(true)
  })

  it('OP_LEFT clamps n greater than the length', function () {
    yields(function (s) { s.add(Opcode.OP_10).add(Opcode.OP_LEFT) }, 'aabbccdd').should.equal(true)
  })

  it('OP_RIGHT clamps n greater than the length', function () {
    yields(function (s) { s.add(Opcode.OP_10).add(Opcode.OP_RIGHT) }, 'aabbccdd').should.equal(true)
  })

  it('rejects a negative size', function () {
    errors(function (s) { s.add(Opcode.OP_1NEGATE).add(Opcode.OP_LEFT) }).should.equal(true)
  })

  it('rejects OP_LEFT with too few stack items', function () {
    const interp = new Interpreter()
    const lock = new Script().add(Opcode.OP_LEFT) // nothing to operate on
    interp.verify(new Script(), lock, new Transaction(), 0, 0).should.equal(false)
  })
})
