'use strict'

/* global describe, it */

// A push declaring more bytes than the script carries is a DECODE failure, and the node
// discovers it reading the instruction, above every per-instruction check:
//
//   if (!script.GetOp(pc, opcode, vchPushValue))
//       return SCRIPT_ERR_BAD_OPCODE;                     // interpreter.cpp:450-451
//
// It therefore outranks the push-size, op-count, disabled-opcode and minimal-push checks, and
// it is not subject to fExec: a malformed push inside a branch that never runs still kills the
// script, because decoding happens before the branch is considered.
//
// This library had the check, in the wrong place twice over: inside `if (fExec && isPush)` and
// after the minimal-push test. So a non-minimal truncated push reported MINIMALDATA, and one
// in an unexecuted branch was tolerated entirely, the script running on to report
// UNBALANCED_CONDITIONAL. The VERDICT was reject in both cases, which is why neither our own
// corpus nor an accept/reject comparison against anyone else's could see it: 24 rows of a
// 24,568-row corpus differed from a compiled bitcoin-sv v1.2.3 only in the reason given.

require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const BN = bsv.crypto.BN

describe('an undecodable push is BAD_OPCODE, before anything else', function () {
  // mainnetFlags() carries FORKID, so verify() needs the satoshi amount.
  function errOf (hex) {
    const interp = new Interpreter()
    interp.verify(new Script(), Script.fromBuffer(Buffer.from(hex, 'hex')),
      new bsv.Transaction(), 0, Interpreter.mainnetFlags(), new BN(1000))
    return interp.errstr || ''
  }

  it('outranks MINIMALDATA, which used to win on a non-minimal truncated push', function () {
    // 0x02 declares two bytes with one left. The chunk is also a non-minimal push of the one
    // byte it carries, so both checks apply and the node reaches the decode failure first.
    errOf('5102ff').should.equal('SCRIPT_ERR_BAD_OPCODE')
    // 0x4b declares 75 bytes with one left.
    errOf('514baa').should.equal('SCRIPT_ERR_BAD_OPCODE')
    // 0x01 declares one byte with none left.
    errOf('5101').should.equal('SCRIPT_ERR_BAD_OPCODE')
  })

  it('applies inside a branch that never executes', function () {
    // OP_0 OP_IF <truncated>. The branch is not taken and there is no OP_ENDIF, so this used
    // to be reported as UNBALANCED_CONDITIONAL — the end-of-script check, reached because the
    // malformed push was skipped as unexecuted. The node never gets that far.
    errOf('006302ff').should.equal('SCRIPT_ERR_BAD_OPCODE')
    // And in a branch that is taken, for symmetry.
    errOf('516302ff').should.equal('SCRIPT_ERR_BAD_OPCODE')
  })

  it('still distinguishes a genuinely unbalanced conditional', function () {
    // No truncation here: the conditional really is unbalanced, and that is what should be
    // reported. Without this case the test above would pass if BAD_OPCODE were returned for
    // every malformed-looking script.
    errOf('0063').should.equal('SCRIPT_ERR_UNBALANCED_CONDITIONAL')
  })

  it('leaves well-formed scripts alone', function () {
    const ok = new Interpreter()
    ok.verify(new Script(), Script.fromBuffer(Buffer.from('51', 'hex')),
      new bsv.Transaction(), 0, Interpreter.mainnetFlags(), new BN(1000)).should.equal(true)
    // A well-formed 2-byte push followed by more script is NOT truncated.
    errOf('5102ff6875').should.not.equal('SCRIPT_ERR_BAD_OPCODE')
    errOf('5100').should.equal('SCRIPT_ERR_EVAL_FALSE_IN_STACK')
  })
})
