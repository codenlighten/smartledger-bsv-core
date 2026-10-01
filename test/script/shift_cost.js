'use strict'

/* global describe, it */

// OP_LSHIFT and OP_RSHIFT cost one pass over the OPERAND, never work proportional to the shift
// COUNT.
//
// The node establishes both the verdict and the shape:
//
//   CScriptNum n{top, requireMinimal, params.MaxScriptNumLength(), utxo_after_genesis};
//   if(n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;
//   if(n >= values.size() * bits_per_byte) fill(begin(values), end(values), 0);
//   else { ... LShift(values, n.getint()) ... }
//
// and its LShift allocates `valtype result(x.size(), 0x00)` and loops over x.size(). So a shift
// of the operand's whole width or more is that many zero bytes, reached without ever converting
// the count to a machine integer.
//
// The time assertions are deliberately loose. They exist to catch a return to work proportional
// to the count, which is orders of magnitude, not a regression of a few milliseconds — and a
// tight bound on a shared machine is a test that gets deleted for flaking.

require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const BN = bsv.crypto.BN

const POST = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_GENESIS |
  Interpreter.SCRIPT_UTXO_AFTER_GENESIS
const BUDGET_MS = 2000

function shift (operand, countBN, opcode, flags) {
  const sc = new Script().add(operand).add(countBN.toScriptNumBuffer()).add(opcode)
  const interp = new Interpreter()
  const started = Date.now()
  interp.verify(new Script(), sc, new bsv.Transaction(), 0, flags || POST, new BN(0))
  return { errstr: interp.errstr, stack: interp.stack, ms: Date.now() - started }
}

describe('shift cost follows the operand, not the count', function () {
  this.timeout(30000)

  const counts = [
    ['2^12', new BN(4096)],
    ['2^20', new BN(1048576)],
    ['2^24', new BN(16777216)],
    ['2^31 - 1', new BN(2147483647)],
    ['2^60', new BN('1152921504606846976')]
  ]

  counts.forEach(function (c) {
    it('OP_LSHIFT of a 1-byte operand by ' + c[0] + ' is one zero byte, quickly', function () {
      const r = shift(Buffer.from([0xff]), c[1], 'OP_LSHIFT')
      // n >= 8 * 1, so the whole operand shifts out.
      r.stack.should.have.lengthOf(1)
      r.stack[0].toString('hex').should.equal('00')
      r.ms.should.be.below(BUDGET_MS)
    })

    it('OP_RSHIFT likewise by ' + c[0], function () {
      const r = shift(Buffer.from([0xff]), c[1], 'OP_RSHIFT')
      r.stack.should.have.lengthOf(1)
      r.stack[0].toString('hex').should.equal('00')
      r.ms.should.be.below(BUDGET_MS)
    })
  })

  it('a count wider than a machine integer is still a verdict, not an error', function () {
    // 2^60 exceeds what toNumber() can represent. Converting first threw a RangeError that the
    // evaluator reported as SCRIPT_ERR_UNKNOWN_ERROR; the node gives zero bytes.
    const r = shift(Buffer.from([0xff]), new BN('1152921504606846976'), 'OP_LSHIFT')
    // The script leaves one zero byte, which is false, so EVAL_FALSE is the honest verdict for
    // THIS script. What matters is that the shift itself produced a value instead of throwing:
    // no UNKNOWN_ERROR, and the operand is on the stack.
    r.errstr.should.not.match(/UNKNOWN_ERROR|RangeError|TypeError/)
    r.stack.should.have.lengthOf(1)
    r.stack[0].toString('hex').should.equal('00')
  })

  it('shifts within the operand width still shift', function () {
    const r = shift(Buffer.from([0x01]), new BN(1), 'OP_LSHIFT')
    r.stack[0].toString('hex').should.equal('02')
    const r2 = shift(Buffer.from([0x02]), new BN(1), 'OP_RSHIFT')
    r2.stack[0].toString('hex').should.equal('01')
  })

  it('a multi-byte operand shifts across byte boundaries', function () {
    const r = shift(Buffer.from('0100', 'hex'), new BN(1), 'OP_RSHIFT')
    r.stack[0].toString('hex').should.equal('0080')
    const r2 = shift(Buffer.from('0080', 'hex'), new BN(1), 'OP_LSHIFT')
    r2.stack[0].toString('hex').should.equal('0100')
  })

  it('a negative count is still refused, before any conversion', function () {
    const r = shift(Buffer.from([0xff]), new BN(-1), 'OP_LSHIFT')
    r.errstr.should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
  })

  it('and a large operand is still one pass', function () {
    const big = Buffer.alloc(100000, 0xff)
    const r = shift(big, new BN(799999), 'OP_LSHIFT')
    r.ms.should.be.below(BUDGET_MS)
  })
})
