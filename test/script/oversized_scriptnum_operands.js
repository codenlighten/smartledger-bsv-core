'use strict'

/* global describe, it, before */

/**
 * Oversized script-number OPERANDS: what each opcode answers, by ERROR NAME.
 *
 * Written after an upstream library was found to PANIC on a large OP_SPLIT index -- a slice-bounds
 * crash from comparing a bignum against a length after narrowing it. Neither of our packages has
 * that defect, and this pins why rather than leaving it a one-off measurement:
 *
 *   - `BN.toNumber()` here does NOT throw above 2**53 the way bn.js's does. It returns a lossy
 *     float: 2**151 comes back as 2.85e+45. So nothing crashes, but a bound tested on the
 *     narrowed value is a bound on an APPROXIMATION. It is safe for these opcodes only because
 *     every bound involved (a small buffer length, 2**31-1) sits far below 2**53, where doubles
 *     are exact. That is a property of these bounds, not of the pattern, which is why
 *     OP_NUM2BIN compares its size as a BN BEFORE narrowing.
 *   - `Interpreter.prototype.evaluate` catches anything `step()` throws and reports
 *     `e.scriptErr` or SCRIPT_ERR_UNKNOWN_ERROR, so a throw cannot escape to the caller -- but it
 *     would arrive under the WRONG NAME. Both halves are asserted: no escaped throw, and no
 *     UNKNOWN_ERROR anywhere in the table.
 *
 * THE BOUNDARY VALUES ARE CONFIRMED AGAINST THE NODE'S SOURCE, not just against ourselves.
 * bsv-core is a port of this code, so the two agreeing is not independent evidence; these four
 * bounds were read from bitcoin-sv v1.2.3 `src/script/interpreter.cpp` on 2026-10-16:
 *
 *   OP_LEFT    (line 660)  if(len < 0 || len > size)            -> SCRIPT_ERR_INVALID_NUMBER_RANGE
 *   OP_RIGHT   (line 685)  if(len < 0 || len > size)            -> same bound, same error
 *   OP_SUBSTR  (line 629)  if(offset < 0 || offset >= size ||
 *                             len < 0 || len > size - offset)   -> SCRIPT_ERR_INVALID_NUMBER_RANGE
 *   OP_SPLIT   (line 1718) if(n < 0 || n > INT32_MAX ||
 *                             n > std::ssize(data))             -> SCRIPT_ERR_INVALID_SPLIT_RANGE
 *
 * So the asymmetry this table pins is the node's, not an accident of ours: LEFT and RIGHT share
 * `len > size` and therefore ACCEPT n == size, while SUBSTR's `offset >= size` REFUSES beg == size.
 * OP_SPLIT accepts pos == size and refuses pos == size + 1. Our measured column matches all four.
 *
 * One node term we do not reproduce literally and do not need to: OP_SPLIT's `n > INT32_MAX` is
 * subsumed by `n > ssize(data)` for any reachable stack element, and both arms return the same
 * error, so the verdict and the name agree either way.

 * The table is GENERATED from a measurement, never transcribed -- a hand-copied count is how
 * this family of mistake reaches a fixture in the first place.
 *
 * The boundary operands (len-1, len, len+1) are load-bearing and were added after a sabotage:
 * turning OP_SPLIT's `position > buf1.length` into `>=` left an earlier 70-case version of this
 * table entirely green, because no operand equalled the buffer length. Note the opcodes do not
 * agree at the boundary -- OP_LEFT accepts n == len where OP_SUBSTR refuses beg == len -- so the
 * boundary is pinned per opcode rather than assumed uniform.
 *
 * SABOTAGE RESULTS (each reverted): OP_SPLIT bound off by one -> caught by pos=8 (len); the
 * SCRIPTNUM_OVERFLOW error name renamed -> 11 failures; OP_NUM2BIN's bound moved onto the
 * narrowed value -> NOT caught, and deliberately recorded as not caught, because it changes no
 * verdict for any operand reachable here (that is the measured reason the order is a robustness
 * choice and not a bug fix).
 *
 * The identical table lives in @smartledger/bsv's test/script/oversized_scriptnum_operands.js.
 * Two copies is the point: the packages agreed on all 91 cases with 0 differences when this was
 * written, so a future divergence fails one of them instead of going unnoticed.
 */

require('chai').should() // the should-style assertion extension; not referenced by name here
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = Script.Interpreter
const Opcode = bsv.Opcode
const BN = bsv.crypto.BN

const OPERANDS = {
  0: new BN(0),
  1: new BN(1),
  '7 (len-1)': new BN(7),
  '8 (len)': new BN(8),
  '9 (len+1)': new BN(9),
  '-1': new BN(-1),
  '2^31-1': new BN(2).pow(new BN(31)).subn(1),
  '2^31': new BN(2).pow(new BN(31)),
  '2^53+1': new BN(2).pow(new BN(53)).addn(1),
  '2^63': new BN(2).pow(new BN(63)),
  '2^151': new BN(2).pow(new BN(151)),
  '-2^63': new BN(2).pow(new BN(63)).neg(),
  '600B zero': Buffer.alloc(600, 0)
}

// [opcode, operand label, expected errstr or 'ACCEPT']
const TABLE = [
  ['OP_LEFT', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_LEFT', '-2^63', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_LEFT', '0', 'ACCEPT'],
  ['OP_LEFT', '1', 'ACCEPT'],
  ['OP_LEFT', '2^151', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LEFT', '2^31', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_LEFT', '2^31-1', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_LEFT', '2^53+1', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_LEFT', '2^63', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LEFT', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_LEFT', '7 (len-1)', 'ACCEPT'],
  ['OP_LEFT', '8 (len)', 'ACCEPT'],
  ['OP_LEFT', '9 (len+1)', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_LSHIFTNUM', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_LSHIFTNUM', '-2^63', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_LSHIFTNUM', '0', 'ACCEPT'],
  ['OP_LSHIFTNUM', '1', 'ACCEPT'],
  ['OP_LSHIFTNUM', '2^151', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LSHIFTNUM', '2^31', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LSHIFTNUM', '2^31-1', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LSHIFTNUM', '2^53+1', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LSHIFTNUM', '2^63', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_LSHIFTNUM', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_LSHIFTNUM', '7 (len-1)', 'ACCEPT'],
  ['OP_LSHIFTNUM', '8 (len)', 'ACCEPT'],
  ['OP_LSHIFTNUM', '9 (len+1)', 'ACCEPT'],
  ['OP_NUM2BIN', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_NUM2BIN', '-2^63', 'SCRIPT_ERR_PUSH_SIZE'],
  ['OP_NUM2BIN', '0', 'SCRIPT_ERR_IMPOSSIBLE_ENCODING'],
  ['OP_NUM2BIN', '1', 'ACCEPT'],
  ['OP_NUM2BIN', '2^151', 'SCRIPT_ERR_PUSH_SIZE'],
  ['OP_NUM2BIN', '2^31', 'SCRIPT_ERR_PUSH_SIZE'],
  ['OP_NUM2BIN', '2^31-1', 'ACCEPT'],
  ['OP_NUM2BIN', '2^53+1', 'SCRIPT_ERR_PUSH_SIZE'],
  ['OP_NUM2BIN', '2^63', 'SCRIPT_ERR_PUSH_SIZE'],
  ['OP_NUM2BIN', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_NUM2BIN', '7 (len-1)', 'ACCEPT'],
  ['OP_NUM2BIN', '8 (len)', 'ACCEPT'],
  ['OP_NUM2BIN', '9 (len+1)', 'ACCEPT'],
  ['OP_RIGHT', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_RIGHT', '-2^63', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_RIGHT', '0', 'ACCEPT'],
  ['OP_RIGHT', '1', 'ACCEPT'],
  ['OP_RIGHT', '2^151', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_RIGHT', '2^31', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_RIGHT', '2^31-1', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_RIGHT', '2^53+1', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_RIGHT', '2^63', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_RIGHT', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_RIGHT', '7 (len-1)', 'ACCEPT'],
  ['OP_RIGHT', '8 (len)', 'ACCEPT'],
  ['OP_RIGHT', '9 (len+1)', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_RSHIFTNUM', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_RSHIFTNUM', '-2^63', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_RSHIFTNUM', '0', 'ACCEPT'],
  ['OP_RSHIFTNUM', '1', 'ACCEPT'],
  ['OP_RSHIFTNUM', '2^151', 'SCRIPT_ERR_BIG_INT'],
  ['OP_RSHIFTNUM', '2^31', 'SCRIPT_ERR_BIG_INT'],
  ['OP_RSHIFTNUM', '2^31-1', 'ACCEPT'],
  ['OP_RSHIFTNUM', '2^53+1', 'SCRIPT_ERR_BIG_INT'],
  ['OP_RSHIFTNUM', '2^63', 'SCRIPT_ERR_BIG_INT'],
  ['OP_RSHIFTNUM', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_RSHIFTNUM', '7 (len-1)', 'ACCEPT'],
  ['OP_RSHIFTNUM', '8 (len)', 'ACCEPT'],
  ['OP_RSHIFTNUM', '9 (len+1)', 'ACCEPT'],
  ['OP_SPLIT', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_SPLIT', '-2^63', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SPLIT', '0', 'ACCEPT'],
  ['OP_SPLIT', '1', 'ACCEPT'],
  ['OP_SPLIT', '2^151', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SPLIT', '2^31', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SPLIT', '2^31-1', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SPLIT', '2^53+1', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SPLIT', '2^63', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SPLIT', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_SPLIT', '7 (len-1)', 'ACCEPT'],
  ['OP_SPLIT', '8 (len)', 'ACCEPT'],
  ['OP_SPLIT', '9 (len+1)', 'SCRIPT_ERR_INVALID_SPLIT_RANGE'],
  ['OP_SUBSTR', '-1', 'SCRIPT_ERR_MINIMALDATA'],
  ['OP_SUBSTR', '-2^63', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_SUBSTR', '0', 'ACCEPT'],
  ['OP_SUBSTR', '1', 'ACCEPT'],
  ['OP_SUBSTR', '2^151', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_SUBSTR', '2^31', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_SUBSTR', '2^31-1', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_SUBSTR', '2^53+1', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_SUBSTR', '2^63', 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'],
  ['OP_SUBSTR', '600B zero', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE'],
  ['OP_SUBSTR', '7 (len-1)', 'ACCEPT'],
  ['OP_SUBSTR', '8 (len)', 'SCRIPT_ERR_INVALID_NUMBER_RANGE'],
  ['OP_SUBSTR', '9 (len+1)', 'SCRIPT_ERR_INVALID_NUMBER_RANGE']
]

function pushNum (s, v) {
  if (Buffer.isBuffer(v)) { s.add(v); return }
  if (v.cmpn(0) === 0) { s.add(Opcode.OP_0); return }
  if (v.cmpn(0) > 0 && v.cmpn(17) < 0) { s.add(Opcode.OP_1 + v.toNumber() - 1); return }
  s.add(v.toScriptNumBuffer())
}

const GENESIS = Interpreter.SCRIPT_UTXO_AFTER_GENESIS | Interpreter.SCRIPT_VERIFY_MINIMALDATA
const CHRONICLE = (Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE || 0) | GENESIS

// The 8-byte operand is what makes '8 (len)' a boundary; don't change it without regenerating.
const EIGHT = function () { return Buffer.alloc(8, 0x42) }

const BUILD = {
  OP_SPLIT: [function (s, v) { s.add(EIGHT()); pushNum(s, v); s.add(Opcode.OP_SPLIT) }, GENESIS],
  OP_NUM2BIN: [function (s, v) { s.add(Opcode.OP_1); pushNum(s, v); s.add(Opcode.OP_NUM2BIN) }, GENESIS],
  OP_LEFT: [function (s, v) { s.add(EIGHT()); pushNum(s, v); s.add(Opcode.OP_LEFT) }, CHRONICLE],
  OP_RIGHT: [function (s, v) { s.add(EIGHT()); pushNum(s, v); s.add(Opcode.OP_RIGHT) }, CHRONICLE],
  OP_SUBSTR: [function (s, v) { s.add(EIGHT()); pushNum(s, v); s.add(Opcode.OP_1); s.add(Opcode.OP_SUBSTR) }, CHRONICLE],
  OP_LSHIFTNUM: [function (s, v) { s.add(Opcode.OP_1); pushNum(s, v); s.add(Opcode.OP_LSHIFTNUM) }, CHRONICLE],
  OP_RSHIFTNUM: [function (s, v) { s.add(Opcode.OP_1); pushNum(s, v); s.add(Opcode.OP_RSHIFTNUM) }, CHRONICLE]
}

function run (op, label) {
  const spec = BUILD[op]
  const s = new Script()
  spec[0](s, OPERANDS[label])
  const i = new Interpreter()
  i.set({ script: s, tx: new bsv.Transaction(), nin: 0, flags: spec[1], satoshisBN: new BN(0) })
  try {
    const ok = i.evaluate()
    return ok ? 'ACCEPT' : (i.errstr || '(no errstr)')
  } catch (e) {
    return 'ESCAPED_THROW:' + e.constructor.name
  }
}

describe('oversized script-number operands', function () {
  // Evaluated ONCE: a 600-byte operand through the shift opcodes is not fast, and re-running the
  // whole table per assertion pushed this file past the default timeout.
  this.timeout(60000)
  const RESULTS = {}
  before(function () {
    TABLE.forEach(function (r) { RESULTS[r[0] + ' ' + r[1]] = run(r[0], r[1]) })
  })

  it('the table is the expected size and is not nearly constant', function () {
    TABLE.length.should.equal(91)
    const outcomes = {}
    TABLE.forEach(function (r) { outcomes[r[2]] = true })
    Object.keys(outcomes).length.should.be.above(4,
      'the expected column is nearly constant - the table is not discriminating')
  })

  it('covers the buffer-length boundary for every range-checking opcode', function () {
    // The hole a sabotage found in the first version of this file.
    ;['OP_SPLIT', 'OP_LEFT', 'OP_RIGHT', 'OP_SUBSTR'].forEach(function (op) {
      ;['7 (len-1)', '8 (len)', '9 (len+1)'].forEach(function (label) {
        TABLE.filter(function (r) { return r[0] === op && r[1] === label })
          .length.should.equal(1, op + ' is missing the boundary operand ' + label)
      })
    })
  })

  TABLE.forEach(function (r) {
    const op = r[0]; const label = r[1]; const expected = r[2]
    it(op + ' with ' + label + ' -> ' + expected, function () {
      RESULTS[op + ' ' + label].should.equal(expected)
    })
  })

  it('no operand makes an exception escape to the caller', function () {
    // The upstream defect that prompted this file was a crash, not a wrong answer.
    TABLE.forEach(function (r) {
      RESULTS[r[0] + ' ' + r[1]].should.not.match(/ESCAPED_THROW/, r[0] + ' ' + r[1])
    })
  })

  it('no operand is answered with a flattened UNKNOWN_ERROR', function () {
    // evaluate() turns an uncaught throw into SCRIPT_ERR_UNKNOWN_ERROR, which rejects under the
    // wrong name. The node names every one of these, so UNKNOWN_ERROR here would be a divergence
    // of the same family as the eight error names closed in 9.31.0 / 1.4.0.
    TABLE.forEach(function (r) {
      RESULTS[r[0] + ' ' + r[1]].should.not.match(/UNKNOWN_ERROR/, r[0] + ' ' + r[1])
    })
  })
})
