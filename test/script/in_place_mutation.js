'use strict'

/* global describe, it, afterEach */

// Opcodes must not write into the buffers they read.
//
// A stack element is not always the interpreter's own memory: a push places
// the script chunk's buffer on the stack, OP_SPLIT returns views into its
// operand, and boolean results are the shared Interpreter.true/false buffers.
// OP_AND, OP_OR, OP_XOR and OP_INVERT used to modify their operand in place,
// and OP_NUM2BIN/OP_BIN2NUM went through _minimallyEncode, which rewrote the
// last byte of its argument. Each of those could therefore
//
//   - rewrite the script being evaluated, including a caller's buffer passed
//     to Script.fromBuffer (and so the script code a later signature covers), or
//   - corrupt Interpreter.true for every evaluation that follows in the same
//     process: after `OP_2 OP_2 OP_3 OP_WITHIN OP_INVERT`, every OP_EQUAL,
//     OP_WITHIN, OP_CHECKSIG... pushed 0xfe instead of 0x01.

require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter

const TRUE = Buffer.from([1])
const FALSE = Buffer.alloc(0)

function run (script, stack) {
  const interp = new Interpreter()
  interp.set({
    script,
    stack: (stack || []).map(function (b) { return Buffer.from(b) }),
    flags: Interpreter.currentConsensusFlags()
  })
  const ok = interp.evaluate()
  return { ok, err: interp.errstr, stack: interp.stack.map(function (b) { return b.toString('hex') }) }
}

function hex (asm) {
  return bsv.Script.fromASM(asm).toBuffer().toString('hex')
}

describe('Interpreter does not mutate the buffers opcodes read', function () {
  afterEach(function () {
    // Keep a failure here from cascading into every other test in the run.
    Interpreter.true = Buffer.from(TRUE)
    Interpreter.false = Buffer.from(FALSE)
  })

  describe('the shared boolean buffers', function () {
    it('OP_INVERT on a boolean result leaves Interpreter.true intact', function () {
      run(bsv.Script.fromASM('OP_2 OP_2 OP_3 OP_WITHIN OP_INVERT')).stack.should.deep.equal(['fe'])
      Interpreter.true.toString('hex').should.equal('01')
      run(bsv.Script.fromASM('OP_2 OP_2 OP_3 OP_WITHIN')).stack.should.deep.equal(['01'])
    })

    it('OP_XOR of two boolean results leaves Interpreter.true intact', function () {
      // Both operands are the same shared buffer, so in place this zeroed it.
      run(bsv.Script.fromASM('OP_1 OP_1 OP_EQUAL OP_2 OP_2 OP_EQUAL OP_XOR')).stack.should.deep.equal(['00'])
      Interpreter.true.toString('hex').should.equal('01')
      run(bsv.Script.fromASM('OP_1 OP_1 OP_EQUAL')).stack.should.deep.equal(['01'])
    })

    it('OP_AND and OP_OR on boolean results leave Interpreter.true intact', function () {
      run(bsv.Script.fromASM('OP_1 OP_1 OP_EQUAL 02 OP_AND')).stack.should.deep.equal(['00'])
      run(bsv.Script.fromASM('OP_1 OP_1 OP_EQUAL 02 OP_OR')).stack.should.deep.equal(['03'])
      Interpreter.true.toString('hex').should.equal('01')
    })
  })

  describe('the script being evaluated', function () {
    const cases = [
      ['OP_INVERT on a pushed constant', '84 OP_INVERT', ['7b']],
      ['OP_AND on pushed constants', '0f 3c OP_AND', ['0c']],
      ['OP_OR on pushed constants', '0f 30 OP_OR', ['3f']],
      ['OP_XOR on pushed constants', '0f 3c OP_XOR', ['33']],
      ['OP_INVERT on an OP_SPLIT view of a push', 'aabb OP_1 OP_SPLIT OP_INVERT', ['aa', '44']],
      ['OP_NUM2BIN of a non-minimal push', '0180 OP_4 OP_NUM2BIN', ['01000080']],
      ['OP_BIN2NUM of a non-minimal push', '0180 OP_BIN2NUM', ['81']]
    ]
    cases.forEach(function (c) {
      it(c[0] + ' computes the result without rewriting the script', function () {
        const original = hex(c[1])
        const caller = Buffer.from(original, 'hex')
        const script = bsv.Script.fromBuffer(caller)
        const r = run(script)
        r.ok.should.equal(true, r.err)
        r.stack.should.deep.equal(c[2])
        script.toBuffer().toString('hex').should.equal(original)
        caller.toString('hex').should.equal(original)
      })

      it(c[0] + ' gives the same result when evaluated twice', function () {
        const script = bsv.Script.fromASM(c[1])
        run(script).stack.should.deep.equal(c[2])
        run(script).stack.should.deep.equal(c[2])
      })
    })
  })

  it('_minimallyEncode returns a new buffer instead of rewriting its argument', function () {
    const input = Buffer.from('0180', 'hex')
    Interpreter._minimallyEncode(input).toString('hex').should.equal('81')
    input.toString('hex').should.equal('0180')
  })
})
