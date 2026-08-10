'use strict'

/* global describe, it */
require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction
const CHRONICLE = Interpreter.SCRIPT_ENABLE_CHRONICLE

// OP_SUBSTR / OP_LEFT / OP_RIGHT — Chronicle string opcodes at 0xb3/0xb4/0xb5.
//
// Every case here passes SCRIPT_ENABLE_CHRONICLE, because without it these
// bytes are UPGRADABLE NOPS, exactly as they are on a pre-Chronicle node. An
// earlier version of these tests ran them with flags=0 and passed, which is
// what hid the fact that the interpreter was executing them unconditionally —
// more permissively than the network.
describe('String opcodes OP_SUBSTR / OP_LEFT / OP_RIGHT', function () {
  const DATA = Buffer.from('aabbccdd', 'hex')

  // Build `<DATA> <ops...>` and assert the top of stack equals `expected`.
  function yields (buildOps, expectedHex) {
    const lock = new Script().add(DATA)
    buildOps(lock)
    lock.add(Buffer.from(expectedHex, 'hex')).add(Opcode.OP_EQUAL)
    const interp = new Interpreter()
    return interp.verify(new Script(), lock, new Transaction(), 0, CHRONICLE)
  }
  function errors (buildOps) {
    const lock = new Script().add(DATA)
    buildOps(lock)
    const interp = new Interpreter()
    let ok
    try { ok = interp.verify(new Script(), lock, new Transaction(), 0, CHRONICLE) } catch (e) { ok = false }
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

  // The node ERRORS rather than clamping:
  //   if(len < 0 || len > size) return SCRIPT_ERR_INVALID_NUMBER_RANGE;
  // Clamping made scripts the node rejects succeed here.
  it('OP_LEFT rejects n greater than the length', function () {
    errors(function (s) { s.add(Opcode.OP_10).add(Opcode.OP_LEFT) }).should.equal(true)
  })

  it('OP_RIGHT rejects n greater than the length', function () {
    errors(function (s) { s.add(Opcode.OP_10).add(Opcode.OP_RIGHT) }).should.equal(true)
  })

  it('is a no-op without SCRIPT_ENABLE_CHRONICLE, as a pre-Chronicle node is', function () {
    const interp = new Interpreter()
    const lock = new Script().add(DATA).add(Opcode.OP_2).add(Opcode.OP_LEFT)
    interp.verify(new Script(), lock, new Transaction(), 0, 0).should.equal(true)
    // Untouched: the opcode did nothing, so both operands survive.
    interp.stack.length.should.equal(2)
  })

  it('rejects a negative size', function () {
    errors(function (s) { s.add(Opcode.OP_1NEGATE).add(Opcode.OP_LEFT) }).should.equal(true)
  })

  it('rejects OP_LEFT with too few stack items', function () {
    const interp = new Interpreter()
    const lock = new Script().add(Opcode.OP_LEFT) // nothing to operate on
    interp.verify(new Script(), lock, new Transaction(), 0, CHRONICLE).should.equal(false)
  })
})
