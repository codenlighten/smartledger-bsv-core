'use strict'

/* global describe, it */
require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction
const BN = bsv.crypto.BN

// verify() defaulted its flags to 0, which is not a neutral default: it is the
// PRE-GENESIS context, specifically and obsoletely. A caller who stated no consensus
// context got the 4-byte script number, the 520-byte element, the 1000-element stack,
// OP_RETURN invalidating outright, and none of the three signature rules BSV enforces
// as mandatory — while the same call in @smartledger/bsv resolved to current mainnet.
//
// The same call asking a different question in each library is the one divergence
// that makes every other comparison between them unreliable.
describe('verify() defaults to current consensus', function () {
  it('resolves undefined flags to currentConsensusFlags()', function () {
    const i = new Interpreter()
    i.verify(new Script(), new Script().add(Opcode.OP_1), new Transaction(), 0, undefined, new BN(0))
    // FORKID is kept here because an amount was supplied.
    i.flags.should.equal(Interpreter.currentConsensusFlags() | Interpreter.SCRIPT_VERIFY_STRICTENC)
  })

  it('strips FORKID when no input amount is available', function () {
    const i = new Interpreter()
    i.verify(new Script(), new Script().add(Opcode.OP_1))
    ;(i.flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID).should.equal(0)
    // Everything else survives, so the era is still current.
    ;(i.flags & Interpreter.SCRIPT_UTXO_AFTER_GENESIS).should.not.equal(0)
    ;(i.flags & Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE).should.not.equal(0)
    ;(i.flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY).should.not.equal(0)
  })

  it('applies the current era, not the 2019 one', function () {
    const i = new Interpreter()
    i.verify(new Script(), new Script().add(Opcode.OP_1))
    i.isAfterGenesis().should.equal(true)
    i.isAfterChronicle().should.equal(true)
    i.maxScriptNumLength().should.equal(32000000)
    i.maxStackSize().should.equal(Interpreter.UNLIMITED)
  })

  // The observable consequence, rather than a restatement of the flag word: a
  // 5-byte script number is an overflow before Genesis and ordinary arithmetic
  // after it, and the default now gives the second answer.
  it('accepts post-Genesis arithmetic that the old default refused', function () {
    const big = new Script()
      .add(Buffer.from('0000000001', 'hex')) // 2^32, five bytes
      .add(Buffer.from('0000000001', 'hex'))
      .add(Opcode.OP_ADD)
      .add(Buffer.from('0000000002', 'hex')) // 2^33
      .add(Opcode.OP_NUMEQUAL)
    const now = new Interpreter()
    now.verify(new Script(), big).should.equal(true)

    // And `flags = 0` still means what it always meant, for anyone who wants it.
    const then = new Interpreter()
    then.verify(new Script(), big, new Transaction(), 0, 0).should.equal(false)
    then.errstr.should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
  })

  it('refuses a non-push unlocking script, which mainnet also refuses', function () {
    const i = new Interpreter()
    i.verify(new Script('OP_1 OP_2 OP_ADD'), new Script('OP_3 OP_EQUAL')).should.equal(false)
    i.errstr.should.equal('SCRIPT_ERR_SIG_PUSHONLY')
  })
})
