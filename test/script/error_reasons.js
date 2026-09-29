'use strict'

/* global describe, it */

// Matching the node's accept/reject verdict is not the same as failing for its reason, and
// the gap between them hid three real defects: OP_DIV and OP_MOD compared a BN against the
// number 0, so `bn2 === 0` was never true, the guard never fired and bn.js asserted instead;
// and a push declaring more bytes than the script carries threw past the evaluator into a
// generic catch. In every case the script still failed, just not in the node's way, so the
// outcome check stayed green through all of them.
//
// Ported from @smartledger/bsv, which reports the node's own reason on all 600 of the rows
// it rejects.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = bsv.Script.Interpreter

function run (sig, pub, flags) {
  const interp = new Interpreter()
  const ok = interp.verify(sig, pub, new bsv.Transaction(), 0,
    flags === undefined ? Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC : flags,
    new bsv.crypto.BN(0))
  return ok ? 'OK' : interp.errstr
}
const asm = (s) => Script.fromASM(s)
const raw = (hex) => Script.fromBuffer(Buffer.from(hex, 'hex'))
// fromASM takes opcodes and hex, not bare decimals, so script numbers are pushed directly.
const nums = (...values) => values.reduce(
  (script, v) => script.add(new bsv.crypto.BN(v).toScriptNumBuffer()), new Script())

describe('failures name the node\'s reason', function () {
  it('a push declaring more bytes than the script carries is BAD_OPCODE', function () {
    // PUSHDATA1/2/4 with not enough bytes, as the node's corpus names them.
    run(raw('4c01'), raw('01' + '61')).should.equal('SCRIPT_ERR_BAD_OPCODE')
    run(raw('4d0200ff'), raw('01' + '61')).should.equal('SCRIPT_ERR_BAD_OPCODE')
    run(raw('4e03000000ffff'), raw('01' + '61')).should.equal('SCRIPT_ERR_BAD_OPCODE')
  })

  it('and does not throw, which became UNKNOWN_ERROR', function () {
    ;(function () { run(raw('4c01'), raw('0161')) }).should.not.throw()
  })

  it('division by zero is DIV_BY_ZERO, and modulo by zero has its own name', function () {
    run(nums(511, 0), asm('OP_DIV')).should.equal('SCRIPT_ERR_DIV_BY_ZERO')
    run(nums(1, 0), asm('OP_MOD')).should.equal('SCRIPT_ERR_MOD_BY_ZERO')
  })

  it('still divides correctly when the denominator is not zero', function () {
    run(nums(7, 3), asm('OP_DIV OP_2 OP_EQUAL')).should.equal('OK')
    run(nums(7, 3), asm('OP_MOD OP_1 OP_EQUAL')).should.equal('OK')
  })

  it('a negative NUM2BIN size is PUSH_SIZE, not IMPOSSIBLE_ENCODING', function () {
    run(nums(-42, -3), asm('OP_NUM2BIN')).should.equal('SCRIPT_ERR_PUSH_SIZE')
  })

  it('while a size too small for the number is still IMPOSSIBLE_ENCODING', function () {
    run(nums(600, 1), asm('OP_NUM2BIN')).should.equal('SCRIPT_ERR_IMPOSSIBLE_ENCODING')
  })
})
