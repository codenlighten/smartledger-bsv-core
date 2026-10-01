'use strict'

/* global describe, it */

// Ported from @smartledger/bsv, where this was fixed first; kept identical so the two
// implementations can be compared line for line.
//
// OP_MUL, OP_LSHIFT, OP_RSHIFT and OP_INVERT run with no flag, because the node runs them with
// no flag.
//
// They used to be refused unless SCRIPT_ENABLE_MAGNETIC_OPCODES was set, "for backwards
// compatibility". The reference node has no such flag at all: IsOpcodeDisabled disables OP_2MUL
// and OP_2DIV and nothing else, so these four execute in every era it can validate. Gating them
// refused 77 rows of the node's own corpus as DISABLED_OPCODE — fail-closed, so nothing was
// wrongly accepted, but they were spends the network accepts.
//
// The node's corpus settles it rather than the source alone: 77 of its rows use these opcodes and
// it expects OK on 66, the other 11 failing for stack, range or overflow reasons. Not one expects
// DISABLED_OPCODE.

require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const BN = bsv.crypto.BN

// Node-style flags: a post-Genesis output, and none of this library's own opcode bits.
const NODE_FLAGS = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_GENESIS |
  Interpreter.SCRIPT_UTXO_AFTER_GENESIS

function run (asm, flags) {
  const interp = new Interpreter()
  const ok = interp.verify(new Script(), Script.fromASM(asm), new bsv.Transaction(), 0,
    flags, new BN(0))
  return ok ? 'OK' : interp.errstr.replace(/^SCRIPT_ERR_/, '')
}

describe('the Magnetic opcodes need no flag, as on the node', function () {
  it('runs OP_MUL, OP_LSHIFT, OP_RSHIFT and OP_INVERT under node-style flags', function () {
    run('OP_3 OP_4 OP_MUL OP_12 OP_EQUAL', NODE_FLAGS).should.equal('OK')
    run('01 OP_1 OP_LSHIFT 02 OP_EQUAL', NODE_FLAGS).should.equal('OK')
    run('02 OP_1 OP_RSHIFT 01 OP_EQUAL', NODE_FLAGS).should.equal('OK')
    run('aabb OP_INVERT 5544 OP_EQUAL', NODE_FLAGS).should.equal('OK')
  })

  it('gives the same answer with the flag set, so setting it is redundant', function () {
    const withFlag = NODE_FLAGS | Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES
    run('OP_3 OP_4 OP_MUL OP_12 OP_EQUAL', withFlag).should.equal('OK')
    run('aabb OP_INVERT 5544 OP_EQUAL', withFlag).should.equal('OK')
  })

  it('still reports a real failure rather than DISABLED_OPCODE', function () {
    // The distinction that matters: an ungated opcode that fails must fail for its own reason.
    run('OP_1 OP_MUL', NODE_FLAGS).should.equal('INVALID_STACK_OPERATION')
    run('OP_INVERT', NODE_FLAGS).should.equal('INVALID_STACK_OPERATION')
  })

  it('keeps OP_2MUL and OP_2DIV disabled until the UTXO is post-Chronicle', function () {
    // These the node DOES gate, on the era of the output being spent. Removing the Magnetic
    // gate must not have loosened these.
    run('OP_2 OP_2MUL OP_4 OP_EQUAL', NODE_FLAGS).should.equal('DISABLED_OPCODE')
    run('OP_4 OP_2DIV OP_2 OP_EQUAL', NODE_FLAGS).should.equal('DISABLED_OPCODE')
    const chronicle = NODE_FLAGS | Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE
    run('OP_2 OP_2MUL OP_4 OP_EQUAL', chronicle).should.equal('OK')
    run('OP_4 OP_2DIV OP_2 OP_EQUAL', chronicle).should.equal('OK')
  })

  it('fails a disabled opcode in an UNEXECUTED branch only before Genesis', function () {
    // The node reads
    //   if(IsOpcodeDisabled(opcode, utxoEra) && (!utxo_after_genesis || fExec))
    // so the era decides whether an unexecuted disabled opcode is fatal. I first asserted it was
    // fatal in both eras; the node says otherwise and this library already agreed with the node.
    const preGenesis = Interpreter.SCRIPT_VERIFY_P2SH
    const unexecuted = 'OP_0 OP_IF OP_2MUL OP_ENDIF OP_1'
    run(unexecuted, preGenesis).should.equal('DISABLED_OPCODE')
    run(unexecuted, NODE_FLAGS).should.equal('OK')
    // Executed, it is fatal in either era.
    run('OP_2 OP_2MUL', preGenesis).should.equal('DISABLED_OPCODE')
    run('OP_2 OP_2MUL', NODE_FLAGS).should.equal('DISABLED_OPCODE')
  })

  // Suggested by the second session auditing this port, from a mutation probe it ran: the gate's
  // reach depended on the era, and removing it must not also un-disable OP_2MUL/OP_2DIV. These
  // are the false-accept side of the claim "removing the Magnetic gate cannot accept anything the
  // node rejects".
  it('runs a Magnetic opcode in an UNEXECUTED branch in BOTH eras', function () {
    // Before the fix this was DISABLED_OPCODE pre-Genesis, because the node's
    //   IsOpcodeDisabled(opcode, era) && (!utxo_after_genesis || fExec)
    // fires on an unexecuted opcode when the UTXO predates Genesis. With OP_MUL no longer
    // disabled, the first operand of that `&&` is false in every era.
    const preGenesis = Interpreter.SCRIPT_VERIFY_P2SH
    run('OP_0 OP_IF OP_MUL OP_ENDIF OP_1', preGenesis).should.equal('OK')
    run('OP_0 OP_IF OP_MUL OP_ENDIF OP_1', NODE_FLAGS).should.equal('OK')
  })

  it('still disables OP_2MUL in an unexecuted branch pre-Genesis', function () {
    // The control. OP_2MUL IS disabled until Chronicle, so the era rule must still bite — this
    // is what would break if the fix had removed too much.
    const preGenesis = Interpreter.SCRIPT_VERIFY_P2SH
    run('OP_0 OP_IF OP_2MUL OP_ENDIF OP_1', preGenesis).should.equal('DISABLED_OPCODE')
    // Post-Genesis an unexecuted disabled opcode is harmless, per the same rule.
    run('OP_0 OP_IF OP_2MUL OP_ENDIF OP_1', NODE_FLAGS).should.equal('OK')
  })

  it('the Monolith opcodes were already ungated and still are', function () {
    run('aa bb OP_CAT aabb OP_EQUAL', NODE_FLAGS).should.equal('OK')
    run('OP_7 OP_3 OP_DIV OP_2 OP_EQUAL', NODE_FLAGS).should.equal('OK')
  })
})
