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

  describe('the length operand is an int64, not a big number', function () {
    // Ported from @smartledger/bsv 9.28.2, where the defect was found. The node builds these
    // operands with CScriptNum's span constructor and does NOT pass `big_int`, which DEFAULTS
    // TO FALSE (src/script/script_num.h), so the value must survive
    // `bsv::deserialize<int64_t>`; the constructor throws SCRIPT_ERR_SCRIPTNUM_OVERFLOW when
    // it will not. `MaxScriptNumLength()` is therefore not the only bound: post-Chronicle it
    // is 32,000,000, and a 600-byte operand clears that and still overflows, because the rule
    // is on the ENCODED LENGTH and not the value.
    //
    // Both libraries read these as big numbers bounded only by maxScriptNumLength() and
    // ACCEPTED a script a compiled node rejects — `script-20261008-14051` from the
    // bsv-lean-proofs corpus, an OP_RIGHT whose length operand was a 600-byte push of zeros.
    // The node's asymmetry is deliberate: OP_SPLIT and OP_NUM2BIN DO pass
    // `utxo_after_genesis` as `big_int`, so they take big numbers after Genesis, while these
    // three string opcodes take an int64 in every era.
    const ERA = Interpreter.SCRIPT_UTXO_AFTER_GENESIS |
                Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE |
                Interpreter.SCRIPT_ENABLE_CHRONICLE

    // `<data> <operand> <op> OP_DROP OP_1` — ends TRUTHY on purpose. A probe that leaves a
    // falsy stack rejects for an unrelated reason (EVAL_FALSE) and cannot see a false accept;
    // that cost a round when this was first measured.
    function errOf (opcode, operandBuf) {
      const lock = new Script().add(DATA).add(operandBuf).add(opcode)
        .add(Opcode.OP_DROP).add(Opcode.OP_1)
      const interp = new Interpreter()
      interp.verify(new Script(), lock, new Transaction(), 0, ERA)
      return interp.errstr || ''
    }

    it('overflows on an operand wider than 9 bytes, whatever its value', function () {
      errOf(Opcode.OP_RIGHT, Buffer.alloc(600)).should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
      errOf(Opcode.OP_LEFT, Buffer.alloc(600)).should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
      errOf(Opcode.OP_RIGHT, Buffer.alloc(10)).should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })

    it('overflows on the 11-byte operand a compiled node rejects', function () {
      errOf(Opcode.OP_RIGHT, Buffer.from('0100000000000000000080', 'hex'))
        .should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })

    it('accepts 9 bytes only when the top byte carries nothing but the sign', function () {
      errOf(Opcode.OP_RIGHT, Buffer.concat([Buffer.alloc(8), Buffer.from([0x00])]))
        .should.not.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
      errOf(Opcode.OP_RIGHT, Buffer.concat([Buffer.alloc(8), Buffer.from([0x01])]))
        .should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })

    it('rejects a 9-byte operand whose low 8 bytes are a negative int64', function () {
      errOf(Opcode.OP_RIGHT,
        Buffer.concat([Buffer.alloc(7), Buffer.from([0x80]), Buffer.from([0x00])]))
        .should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
      errOf(Opcode.OP_RIGHT,
        Buffer.concat([Buffer.alloc(7), Buffer.from([0x80]), Buffer.from([0x80])]))
        .should.not.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })

    it('reports MINENCODE, not OVERFLOW, when the operand fails both', function () {
      // The node's span constructor runs three checks IN ORDER: size against max_length,
      // then minimal encoding, then the int64 fit. An operand that is both non-minimal and
      // wider than 9 bytes must therefore report SCRIPTNUM_MINENCODE, because that is the
      // one the node reaches first.
      //
      // Measured regression: the guard was first placed BEFORE the bignum read and reported
      // OVERFLOW here — the same reject for the wrong reason, on 4 rows of a 24,568-row
      // corpus. An accept/reject comparison cannot see that; only the error name can.
      const WIDE_FLAGS = ERA | Interpreter.SCRIPT_VERIFY_MINIMALDATA
      function errWith (operandBuf) {
        const lock = new Script().add(Buffer.from('aabbccdd', 'hex')).add(operandBuf)
          .add(Opcode.OP_RIGHT).add(Opcode.OP_DROP).add(Opcode.OP_1)
        const interp = new Interpreter()
        interp.verify(new Script(), lock, new Transaction(), 0, WIDE_FLAGS)
        return interp.errstr || ''
      }
      // 12 zero bytes: numerically 0, so non-minimal, and also too wide.
      errWith(Buffer.alloc(12)).should.equal('SCRIPT_ERR_SCRIPTNUM_MINENCODE')
      // Minimal and too wide: the top byte carries value bits, so no shorter encoding exists
      // and the minimal check passes — then the int64 rule fires.
      errWith(Buffer.from('ffffffffffffffffff7f', 'hex'))
        .should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })

    it('still takes an ordinary operand, so the bound did not swallow the honest case', function () {
      const lock = new Script().add(DATA).add(Opcode.OP_2).add(Opcode.OP_RIGHT)
        .add(Buffer.from('ccdd', 'hex')).add(Opcode.OP_EQUAL)
      const interp = new Interpreter()
      interp.verify(new Script(), lock, new Transaction(), 0, ERA).should.equal(true)
    })

    it('bounds both of OP_SUBSTR\'s operands, the length one first', function () {
      const wide = Buffer.alloc(12)
      const lock = new Script().add(DATA).add(wide).add(wide).add(Opcode.OP_SUBSTR)
      const interp = new Interpreter()
      interp.verify(new Script(), lock, new Transaction(), 0, ERA)
      interp.errstr.should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })

    it('leaves OP_SPLIT on big numbers, as the node does', function () {
      // The contrast that makes the rule a rule and not a guess.
      const lock = new Script().add(DATA).add(Buffer.alloc(12)).add(Opcode.OP_SPLIT)
      const interp = new Interpreter()
      interp.verify(new Script(), lock, new Transaction(), 0, ERA)
      interp.errstr.should.not.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
    })
  })
})
