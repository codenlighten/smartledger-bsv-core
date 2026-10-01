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
// the count to a machine integer, and without allocating a value of the shifted width.
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

  it('a count too wide to allocate is still a verdict, not an error', function () {
    // The old path called bn.ushln(n), which allocates a value of the SHIFTED width. At this
    // count the implied array length is invalid and bn.js raises a RangeError, which the
    // evaluator reported as SCRIPT_ERR_UNKNOWN_ERROR. The node gives zero bytes. Note it is
    // ushln that raises, not the narrowing: bn.js 4.12.5's toNumber() never throws — it rounds
    // past 2^53 and returns Infinity at extreme widths.
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
  // The count is validated whatever the operand is. There used to be an early-out when the
  // operand was empty, which skipped the decode and therefore all three of its checks, so an
  // invalid count was accepted whenever the value happened to be empty. The node's only guard
  // before the decode is `stack.size() < 2`.
  describe('the count is validated even when the operand is empty', function () {
    const PRE = Interpreter.SCRIPT_VERIFY_P2SH

    function shiftEmpty (countBuf, opcode, flags) {
      const sc = new Script().add(Buffer.alloc(0)).add(countBuf).add(opcode)
      const interp = new Interpreter()
      interp.verify(new Script(), sc, new bsv.Transaction(), 0, flags, new BN(0))
      return interp.errstr.replace(/^SCRIPT_ERR_/, '')
    }

    it('refuses a negative count', function () {
      shiftEmpty(new BN(-1).toScriptNumBuffer(), 'OP_LSHIFT', POST)
        .should.equal('INVALID_NUMBER_RANGE')
      shiftEmpty(new BN(-1).toScriptNumBuffer(), 'OP_RSHIFT', POST)
        .should.equal('INVALID_NUMBER_RANGE')
    })

    it('refuses a count too wide for the era', function () {
      shiftEmpty(Buffer.from('0100000001', 'hex'), 'OP_LSHIFT', PRE)
        .should.equal('SCRIPTNUM_OVERFLOW')
    })

    it('refuses a non-minimally-encoded count when asked', function () {
      shiftEmpty(Buffer.from('0100', 'hex'), 'OP_LSHIFT',
        POST | Interpreter.SCRIPT_VERIFY_MINIMALDATA).should.equal('SCRIPTNUM_MINENCODE')
    })

    it('and accepts a valid count, returning an empty result', function () {
      const sc = new Script().add(Buffer.alloc(0)).add('OP_1').add('OP_LSHIFT')
        .add('OP_SIZE').add('OP_0').add('OP_EQUAL')
      const interp = new Interpreter()
      const ok = interp.verify(new Script(), sc, new bsv.Transaction(), 0, POST, new BN(0))
      ok.should.equal(true)
    })
  })

  // OP_NUM2BIN's size is capped at INT32_MAX in EVERY era, before the element-size test. The
  // era only widens the second test. Without the first, a size above INT32_MAX passed the
  // post-Genesis element check — effectively unbounded — and the allocation followed the
  // operand's value rather than its length.
  describe('OP_NUM2BIN size is bounded by INT32_MAX in every era', function () {
    function num2bin (sizeBN, flags) {
      const sc = new Script().add('OP_1').add(sizeBN.toScriptNumBuffer()).add('OP_NUM2BIN')
      const interp = new Interpreter()
      const started = Date.now()
      interp.verify(new Script(), sc, new bsv.Transaction(), 0, flags || POST, new BN(0))
      return { errstr: interp.errstr.replace(/^SCRIPT_ERR_/, ''), ms: Date.now() - started }
    }

    it('refuses a size above INT32_MAX without allocating', function () {
      const r = num2bin(new BN('10737418240'))
      r.errstr.should.equal('PUSH_SIZE')
      r.ms.should.be.below(BUDGET_MS)
    })

    it('refuses INT32_MAX + 1', function () {
      num2bin(new BN(2147483648)).errstr.should.equal('PUSH_SIZE')
    })

    it('still refuses a negative size as a push size failure', function () {
      num2bin(new BN(-1)).errstr.should.equal('PUSH_SIZE')
    })

    it('and still refuses anything over 520 bytes before Genesis', function () {
      num2bin(new BN(521), Interpreter.SCRIPT_VERIFY_P2SH).errstr.should.equal('PUSH_SIZE')
      num2bin(new BN(4), Interpreter.SCRIPT_VERIFY_P2SH).errstr.should.equal('')
    })
  })
})
