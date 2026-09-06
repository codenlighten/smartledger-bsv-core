'use strict'

/* global describe, it, beforeEach, afterEach */
const should = require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction

// Post-Genesis BSV removed the pre-Genesis script limits (520-byte element,
// 4-byte script number, 201 opcodes). These are now configurable so modern
// covenants (e.g. OP_PUSH_TX) can be evaluated. Defaults are unchanged.
describe('Interpreter post-Genesis limits', function () {
  let saved

  beforeEach(function () {
    saved = Interpreter.getLimits()
  })
  afterEach(function () {
    Interpreter.setLimits(saved)
  })

  it('keeps pre-Genesis defaults out of the box', function () {
    Interpreter.MAX_SCRIPT_ELEMENT_SIZE.should.equal(520)
    Interpreter.MAXIMUM_ELEMENT_SIZE.should.equal(4)
    Interpreter.MAX_OPS_PER_SCRIPT.should.equal(201)
  })

  // MAXIMUM_ELEMENT_SIZE is no longer among them. It is CScriptNum's max_length,
  // and since the limits became era-derived it is only the PRE-Genesis fallback —
  // raising it could not enable post-Genesis arithmetic, only corrupt pre-Genesis
  // validation.
  it('useGenesisLimits() lifts the size caps but not the script-number bound', function () {
    Interpreter.useGenesisLimits()
    Interpreter.MAX_SCRIPT_ELEMENT_SIZE.should.equal(0x7fffffff)
    Interpreter.MAX_OPS_PER_SCRIPT.should.equal(0x7fffffff)
    Interpreter.MAXIMUM_ELEMENT_SIZE.should.equal(4)
  })

  // The reason it must not be raised, stated as a test: a 5-byte operand is an
  // overflow before Genesis, and no process-wide call may turn that into an accept.
  it('cannot be made to accept a pre-Genesis script-number overflow', function () {
    const overflow = new Script()
      .add(Buffer.from('1234567890', 'hex'))
      .add(Buffer.from([2]))
      .add(Opcode.OP_MUL)
    const flags = Interpreter.SCRIPT_VERIFY_P2SH | Interpreter.SCRIPT_VERIFY_STRICTENC |
      Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES | Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES
    Interpreter.useGenesisLimits()
    const interp = new Interpreter()
    interp.verify(new Script(), overflow, new Transaction(), 0, flags).should.equal(false)
    // The exact code the node uses. This asserted only on substance while the port
    // still flattened the throw into SCRIPT_ERR_UNKNOWN_ERROR; that divergence
    // against @smartledger/bsv is now closed, so the assertion can be exact.
    interp.errstr.should.equal('SCRIPT_ERR_SCRIPTNUM_OVERFLOW')
  })

  // <2^32> <2^32> OP_ADD <2^33> OP_NUMEQUAL  — operands exceed the 4-byte cap.
  const bigAdd = new Script()
    .add(Buffer.from('0000000001', 'hex')) // 2^32, little-endian, 5 bytes
    .add(Buffer.from('0000000001', 'hex'))
    .add(Opcode.OP_ADD)
    .add(Buffer.from('0000000002', 'hex')) // 2^33
    .add(Opcode.OP_NUMEQUAL)

  function run (lock) {
    const interp = new Interpreter()
    let ok
    try { ok = interp.verify(new Script(), lock, new Transaction(), 0, 0) } catch (e) { ok = false }
    return ok
  }

  it('rejects >4-byte arithmetic under default limits', function () {
    run(bigAdd).should.equal(false)
  })

  // Post-Genesis arithmetic is reached through the ERA, not through the static.
  // useGenesisLimits() used to be the only route; it no longer is, and using it for
  // this would corrupt pre-Genesis validation elsewhere in the same process.
  it('allows >4-byte arithmetic when the post-Genesis era is asked for', function () {
    const interp = new Interpreter()
    interp.verify(new Script(), bigAdd, new Transaction(), 0,
      Interpreter.SCRIPT_UTXO_AFTER_GENESIS).should.equal(true)
  })

  it('still rejects it under pre-Genesis rules, whatever the statics say', function () {
    Interpreter.useGenesisLimits()
    run(bigAdd).should.equal(false)
  })

  // 220 OP_NOPs then OP_1 — more non-push opcodes than the 201 cap allows.
  const manyOps = new Script()
  for (let i = 0; i < 220; i++) manyOps.add(Opcode.OP_NOP)
  manyOps.add(Opcode.OP_1)

  it('rejects >201 opcodes under default limits', function () {
    run(manyOps).should.equal(false)
  })

  it('allows >201 opcodes after useGenesisLimits()', function () {
    Interpreter.useGenesisLimits()
    run(manyOps).should.equal(true)
  })
  // Total script size was a hard-coded 10,000 in evaluate(), so useGenesisLimits()
  // could not lift it: any script over 10 KB failed SCRIPT_ERR_SCRIPT_SIZE regardless
  // of what the caller asked for. That put every sizeable 1Sat Ordinals inscription
  // out of reach of the interpreter entirely.
  function scriptOfSize (bytes) {
    // OP_DROP a single large push, then OP_1 — trivially true, but big.
    return new Script()
      .add(Buffer.alloc(bytes))
      .add(Opcode.OP_DROP)
      .add(Opcode.OP_1)
  }

  it('exposes the total script size cap as a constant, defaulting to pre-Genesis', function () {
    Interpreter.MAX_SCRIPT_SIZE.should.equal(10000)
  })

  // Stated explicitly rather than left to the default, which now resolves to current
  // mainnet: post-Genesis the size cap is gone, so a default-flags run would accept
  // this and the test would be measuring nothing. `flags = 0` IS the pre-Genesis
  // context, which is what this asserts.
  it('rejects a >10 KB script under pre-Genesis rules', function () {
    Interpreter.useGenesisLimits() // lift element/ops caps so SIZE is what is under test
    Interpreter.MAX_SCRIPT_SIZE = 10000 // ...but keep the pre-Genesis size cap
    const interp = new Interpreter()
    interp.verify(new Script(), scriptOfSize(20 * 1024), new Transaction(), 0, 0).should.equal(false)
    interp.errstr.should.equal('SCRIPT_ERR_SCRIPT_SIZE')
  })

  it('allows a >10 KB script after useGenesisLimits()', function () {
    Interpreter.useGenesisLimits()
    run(scriptOfSize(20 * 1024)).should.equal(true)
  })

  it('useGenesisLimits raises the size caps, and getLimits/setLimits round-trip', function () {
    const before = Interpreter.getLimits()
    before.maxScriptSize.should.equal(10000)
    Interpreter.useGenesisLimits(64 * 1024)
    const after = Interpreter.getLimits()
    after.maxScriptElementSize.should.equal(64 * 1024)
    // Not raised — see the note on useGenesisLimits. setLimits() can still set it
    // explicitly, which is what the round-trip below checks.
    after.maximumElementSize.should.equal(4)
    after.maxOpsPerScript.should.equal(64 * 1024)
    after.maxScriptSize.should.equal(64 * 1024)
    Interpreter.setLimits(before)
    Interpreter.getLimits().maxScriptSize.should.equal(10000)
    Interpreter.MAX_SCRIPT_ELEMENT_SIZE.should.equal(520)
  })
})
