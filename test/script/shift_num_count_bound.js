'use strict'

/* global describe, it */

// The OP_RSHIFTNUM shift COUNT is bounded by INT32_MAX.
//
// The node hands the count straight to CScriptNum::operator>>= as a CScriptNum —
// interpreter.cpp does `values >>= n;` with no getint(), unlike the bitwise OP_RSHIFT
// beneath it, which calls n.getint() and chunks by INT32_MAX. That operator narrows the
// count to a 32-bit shift internally and raises bsv::big_int_error above INT32_MAX,
// which EvalScript's catch turns into SCRIPT_ERR_BIG_INT.
//
// This library had no such bound. The count fell through to the `shiftBy >= bitLength()`
// short-circuit, the opcode pushed an empty result, and
// `<v> <2^32+1> OP_RSHIFTNUM OP_DROP OP_1` VERIFIED here while failing on the network —
// a FALSE ACCEPT, the direction that leaves coins stranded behind a lock this library
// called good.
//
// Reference verdicts are from a compiled bitcoin-sv v1.2.3 run under flags 0x3d586f:
// every count >= 2^31 aborts with SCRIPT_ERR_BIG_INT, every count <= 2^31-1 shifts, and
// the value is irrelevant because the count is narrowed before anything is shifted.
//
// Found by an outside lab building a locking-script catalogue on this package, not by
// this suite — every count case it already had sits far below the boundary.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Opcode = bsv.Opcode
const Interpreter = bsv.Script.Interpreter
const BN = bsv.crypto.BN

// The node's shape: the UTXO is post-Chronicle, which is what makes these opcodes live.
const ERA = Interpreter.SCRIPT_VERIFY_P2SH |
  Interpreter.SCRIPT_UTXO_AFTER_GENESIS |
  Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE

const INT32_MAX = 2147483647

// `<x> <n> <op>`: the node's comment is literally `(x n -- out)`, so the COUNT is on top.
function shift (x, n, op) {
  const script = new Script()
    .add(x instanceof BN ? x.toScriptNumBuffer() : new BN(x).toScriptNumBuffer())
    .add(n instanceof BN ? n.toScriptNumBuffer() : new BN(n).toScriptNumBuffer())
    .add(op)
  const interp = new Interpreter()
  const ok = interp.verify(new Script(), script, new bsv.Transaction(), 0, ERA,
    new bsv.crypto.BN(0))
  return { ok, errstr: interp.errstr }
}

// A zero result fails EVAL_FALSE, so compare against OP_0 to assert "shifted to zero".
function shiftsToZero (x, n, op) {
  const script = new Script()
    .add(new BN(x).toScriptNumBuffer())
    .add(n instanceof BN ? n.toScriptNumBuffer() : new BN(n).toScriptNumBuffer())
    .add(op).add(Opcode.OP_0).add(Opcode.OP_EQUAL)
  const interp = new Interpreter()
  return interp.verify(new Script(), script, new bsv.Transaction(), 0, ERA,
    new bsv.crypto.BN(0))
}

describe('OP_RSHIFTNUM bounds the shift count by INT32_MAX', function () {
  it('shifts for every count up to INT32_MAX', function () {
    shiftsToZero(5, INT32_MAX, Opcode.OP_RSHIFTNUM).should.equal(true)
    shiftsToZero(5, INT32_MAX - 1, Opcode.OP_RSHIFTNUM).should.equal(true)
    shift(1024, 10, Opcode.OP_RSHIFTNUM).ok.should.equal(true)
  })

  it('aborts with BIG_INT at and above 2^31, where the node does', function () {
    ;[2147483648, 2147483649, 4294967297, 4503599627370496].forEach(function (n) {
      const r = shift(5, n, Opcode.OP_RSHIFTNUM)
      r.ok.should.equal(false, 'count ' + n + ' was accepted')
      r.errstr.should.equal('SCRIPT_ERR_BIG_INT', 'count ' + n)
    })
  })

  it('aborts on a count far past any float precision', function () {
    // BN.prototype.toNumber here is parseInt(toString(10)), which does NOT throw past
    // 2^53 — a 26-byte count narrowed to 4.1e62. So the bound has to be tested on the
    // BN, before narrowing, or it is a bound on a rounded approximation.
    const huge = new BN('ff'.repeat(25) + '7f', 16)
    const r = shift(5, huge, Opcode.OP_RSHIFTNUM)
    r.ok.should.equal(false)
    r.errstr.should.equal('SCRIPT_ERR_BIG_INT')
  })

  it('aborts whatever the value is, because the count is read first', function () {
    // Asserted because "it only matters for large values" is the natural wrong guess,
    // and it would make a narrower fix look sufficient.
    ;[0, 1, -1, -5].forEach(function (x) {
      const r = shift(x, 4294967297, Opcode.OP_RSHIFTNUM)
      r.ok.should.equal(false, 'value ' + x)
      r.errstr.should.equal('SCRIPT_ERR_BIG_INT', 'value ' + x)
    })
  })

  it('still rejects a negative count as NUMBER_RANGE, checked before the bound', function () {
    const r = shift(5, -1, Opcode.OP_RSHIFTNUM)
    r.ok.should.equal(false)
    r.errstr.should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
  })

  it('leaves OP_LSHIFTNUM reporting SCRIPTNUM_OVERFLOW, which the node agrees with', function () {
    // Deliberately NOT given the BIG_INT bound. operator<<= bounds the RESULT size
    // first, and that bound trips above ~256,000,000 — well under INT32_MAX — so the
    // big_int path is unreachable for a left shift in every era where these opcodes are
    // live. Adding the check would swap an agreeing error name for a disagreeing one,
    // which is the defect class 1.4.0's nodeErrstr work went after.
    ;[2147483648, 4294967297].forEach(function (n) {
      const r = shift(5, n, Opcode.OP_LSHIFTNUM)
      r.ok.should.equal(false)
      r.errstr.should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW', 'count ' + n)
    })
  })

  it('yields to the VALUE\'s own error, because the count is not read last', function () {
    // Error PRECEDENCE, which the bound could easily have got wrong. The node builds a
    // CScriptNum for the count, then one for the value, then shifts — so a value failing
    // its OWN validation must report its own error even when the count is also out of
    // range. Measured: a non-minimal value with a 2^32+1 count gives SCRIPTNUM_MINENCODE,
    // not BIG_INT. Had the bound been placed directly after the count was read, this
    // would have returned BIG_INT and diverged again.
    const script = new Script()
      .add(Buffer.from('0500', 'hex'))
      .add(new BN(4294967297).toScriptNumBuffer())
      .add(Opcode.OP_RSHIFTNUM)
    const interp = new Interpreter()
    const ok = interp.verify(new Script(), script, new bsv.Transaction(), 0,
      ERA | Interpreter.SCRIPT_VERIFY_MINIMALDATA, new bsv.crypto.BN(0))
    ok.should.equal(false)
    interp.errstr.should.equal('SCRIPT_ERR_SCRIPTNUM_MINENCODE')
  })

  it('reports BIG_INT for a value that is long but legal', function () {
    // The mirror of the case above: under Chronicle the script-number length is
    // 32,000,000, so a 750,001-byte value is valid and the count's bound is what fires.
    // Confirms the previous test pins precedence and not merely "long values error".
    const script = new Script()
      .add(Buffer.alloc(750001, 1))
      .add(new BN(4294967297).toScriptNumBuffer())
      .add(Opcode.OP_RSHIFTNUM)
    const interp = new Interpreter()
    const ok = interp.verify(new Script(), script, new bsv.Transaction(), 0, ERA,
      new bsv.crypto.BN(0))
    ok.should.equal(false)
    interp.errstr.should.equal('SCRIPT_ERR_BIG_INT')
  })

  it('exempts OP_LSHIFTNUM even for a zero value, where the size bound still fires', function () {
    // The exemption argument rests on the result-size bound running first and applying
    // whatever the value is — a zero value is the case where "the result is too big"
    // reads least obviously, so it is the one worth asserting.
    ;[0, 5].forEach(function (x) {
      shift(x, 4294967297, Opcode.OP_LSHIFTNUM).errstr
        .should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW', 'value ' + x)
    })
    shift(0, INT32_MAX, Opcode.OP_LSHIFTNUM).errstr
      .should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW', 'count at INT32_MAX')
  })

  it('is a NOP before Chronicle, so the bound does not leak backwards', function () {
    // A pre-Chronicle UTXO treats these bytes as upgradable NOPs on the network. The
    // new error must not make this library refuse a script the network accepts — the
    // mirror of the bug being fixed.
    const script = new Script()
      .add(new BN(5).toScriptNumBuffer())
      .add(new BN(4294967297).toScriptNumBuffer())
      .add(Opcode.OP_RSHIFTNUM).add(Opcode.OP_DROP).add(Opcode.OP_DROP).add(Opcode.OP_1)
    const interp = new Interpreter()
    const ok = interp.verify(new Script(), script, new bsv.Transaction(), 0,
      Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_UTXO_AFTER_GENESIS,
      new bsv.crypto.BN(0))
    ok.should.equal(true, interp.errstr)
  })
})
