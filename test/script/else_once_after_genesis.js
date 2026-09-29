'use strict'

/* global describe, it */

// Genesis allows one OP_ELSE per OP_IF. The node states it in one line:
//
//   if (vfExec.empty() || (vfElse.back() && utxo_after_genesis))
//       return set_error(serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
//
// This interpreter tracked only vfExec, so a second OP_ELSE flipped the branch again and
// the script ran on. That accepted 18 rows of the node's own script_tests corpus that the
// node rejects — a false accept, the direction that costs money, since a spend built on
// one is rejected by the network after it looks valid here.
//
// Before Genesis the rule does not apply, and repeated OP_ELSE is legal. Both eras are
// asserted, or a fix in one direction would look like a fix in both.

require('chai').should()
const bsv = require('../..')
const Script = bsv.Script
const Interpreter = bsv.Script.Interpreter

function run (asm, flags) {
  const interp = new Interpreter()
  const ok = interp.verify(new Script(), Script.fromASM(asm), new bsv.Transaction(), 0,
    flags, new bsv.crypto.BN(0))
  return { ok, errstr: interp.errstr }
}

const PRE = Interpreter.SCRIPT_VERIFY_P2SH
const POST = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_UTXO_AFTER_GENESIS

describe('one OP_ELSE per OP_IF after Genesis', function () {
  it('refuses a second OP_ELSE after Genesis', function () {
    const r = run('OP_1 OP_IF OP_ELSE OP_ELSE OP_ENDIF OP_1', POST)
    r.ok.should.equal(false)
    r.errstr.should.equal('SCRIPT_ERR_UNBALANCED_CONDITIONAL')
  })

  it('allows the second OP_ELSE before Genesis, as the node does', function () {
    run('OP_1 OP_IF OP_ELSE OP_ELSE OP_ENDIF OP_1', PRE).ok.should.equal(true)
  })

  it('still allows exactly one OP_ELSE after Genesis', function () {
    run('OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF', POST).ok.should.equal(true)
    run('OP_0 OP_IF OP_0 OP_ELSE OP_1 OP_ENDIF', POST).ok.should.equal(true)
  })

  it('counts the limit per conditional, not per script', function () {
    // One OP_ELSE at each of two depths is legal; a second at the inner depth is not.
    run('OP_1 OP_IF OP_1 OP_IF OP_1 OP_ELSE OP_0 OP_ENDIF OP_ELSE OP_0 OP_ENDIF', POST)
      .ok.should.equal(true)
    run('OP_1 OP_IF OP_1 OP_IF OP_1 OP_ELSE OP_ELSE OP_0 OP_ENDIF OP_ENDIF OP_1', POST)
      .errstr.should.equal('SCRIPT_ERR_UNBALANCED_CONDITIONAL')
  })

  it('still refuses OP_ELSE with no OP_IF open, in either era', function () {
    run('OP_1 OP_ELSE OP_ENDIF', POST).errstr.should.equal('SCRIPT_ERR_UNBALANCED_CONDITIONAL')
    run('OP_1 OP_ELSE OP_ENDIF', PRE).errstr.should.equal('SCRIPT_ERR_UNBALANCED_CONDITIONAL')
  })
})
