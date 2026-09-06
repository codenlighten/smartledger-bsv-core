'use strict'

/* global describe, it */
const should = require('chai').should()
const bsv = require('../..')
const BN = bsv.crypto.BN
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction

// The stack limits were the last of the pre-Genesis caps still applied as a
// literal, and the only one useGenesisLimits() could not reach. Two divergences
// from the node in five lines, in opposite directions: checked once at the end of
// the script where the node checks after every opcode, and applied after Genesis,
// which removed the element count in favour of a bound on memory.
//
// Ported from @smartledger/bsv 9.7.0, which found both.
describe('Interpreter stack limits', function () {
  const PRE = 0
  const POST = Interpreter.SCRIPT_UTXO_AFTER_GENESIS | Interpreter.SCRIPT_GENESIS

  function run (build, flags) {
    const lock = new Script()
    build(lock, Opcode)
    const i = new Interpreter()
    let ok
    try {
      ok = i.verify(new Script(), lock, new Transaction(), 0, flags)
    } catch (e) {
      return 'threw ' + e.message
    }
    return ok ? 'ACCEPT' : i.errstr
  }

  function pushes (n) {
    return function (s, O) { for (let k = 0; k < n; k++) s.add(O.OP_1) }
  }

  describe('the cap is era-derived', function () {
    it('is 1000 elements before Genesis', function () {
      const i = new Interpreter()
      i.flags = PRE
      i.maxStackSize().should.equal(1000)
      Interpreter.MAX_STACK_SIZE.should.equal(1000)
    })

    it('is removed after Genesis, and nothing is silently put in its place', function () {
      const i = new Interpreter()
      i.flags = POST
      i.maxStackSize().should.equal(Interpreter.UNLIMITED)
      // Post-Genesis CONSENSUS does not bound stack memory either. The node's
      // 100 MB is -maxstackmemoryusagepolicy, a RELAY setting; defaulting to it
      // would refuse scripts the network accepts.
      i.maxStackMemoryUsage().should.equal(Interpreter.UNLIMITED)
      Interpreter.STACK_MEMORY_USAGE_POLICY.should.equal(100 * 1024 * 1024)
    })
  })

  describe('before Genesis', function () {
    it('accepts 999 elements', function () {
      run(pushes(999), PRE).should.equal('ACCEPT')
    })

    it('refuses 1001', function () {
      run(pushes(1001), PRE).should.equal('SCRIPT_ERR_STACK_SIZE')
    })

    // The one no vector covers: both STACK_SIZE vectors in the corpus END over the
    // cap, which is exactly the case an end-of-script check does see.
    //
    // 200 OP_2DROPs, not 400 OP_DROPs: OP_1 is under OP_16 and does not count
    // toward the opcode budget, but the drops do, and this repo's pre-Genesis
    // budget is 201. Written with OP_DROP it trips SCRIPT_ERR_OP_COUNT instead and
    // passes the assertion for the wrong reason.
    it('refuses a script that exceeds the cap and then drops back under it', function () {
      run(function (s, O) {
        for (let k = 0; k < 1001; k++) s.add(O.OP_1)
        for (let d = 0; d < 200; d++) s.add(O.OP_2DROP)
      }, PRE).should.equal('SCRIPT_ERR_STACK_SIZE')
    })

    it('counts the altstack toward the same cap', function () {
      run(function (s, O) {
        for (let k = 0; k < 900; k++) s.add(O.OP_1)
        for (let t = 0; t < 150; t++) s.add(O.OP_TOALTSTACK)
        for (let j = 0; j < 150; j++) s.add(O.OP_1)
      }, PRE).should.equal('SCRIPT_ERR_STACK_SIZE')
    })
  })

  describe('after Genesis', function () {
    it('accepts 1001 elements, which the node does', function () {
      run(pushes(1001), POST).should.equal('ACCEPT')
    })

    it('accepts far more than the old cap', function () {
      run(pushes(5000), POST).should.equal('ACCEPT')
    })

    it('does not apply the relay policy ceiling unless asked', function () {
      const i = new Interpreter()
      i.flags = POST
      i.maxStackMemoryUsage().should.equal(Interpreter.UNLIMITED)
      should.equal(i.checkStackLimits(), null)
    })

    it('bounds the memory once a caller opts in', function () {
      const saved = Interpreter.MAX_STACK_MEMORY_USAGE_AFTER_GENESIS
      try {
        // A ceiling low enough that a few dozen elements exceed it, so the bound is
        // exercised without allocating 100 MB in a unit test.
        Interpreter.MAX_STACK_MEMORY_USAGE_AFTER_GENESIS = 500
        run(pushes(100), POST).should.equal('SCRIPT_ERR_STACK_SIZE')
        Interpreter.MAX_STACK_MEMORY_USAGE_AFTER_GENESIS = Interpreter.STACK_MEMORY_USAGE_POLICY
        const i = new Interpreter()
        i.flags = POST
        i.maxStackMemoryUsage().should.equal(100 * 1024 * 1024)
      } finally {
        Interpreter.MAX_STACK_MEMORY_USAGE_AFTER_GENESIS = saved
      }
    })

    it('charges each element its container overhead, not only its bytes', function () {
      const i = new Interpreter()
      i.flags = POST
      i.stack = [Buffer.alloc(10), Buffer.alloc(20)]
      i.altstack = [Buffer.alloc(0)]
      i.stackMemoryUsage().should.equal(30 + 3 * Interpreter.STACK_ELEMENT_OVERHEAD)
    })
  })

  // Guards against the probe being wrong rather than the interpreter: a BN is what
  // verify() wants for an amount, and these scripts carry no signature.
  it('needs no input amount for these scripts', function () {
    const i = new Interpreter()
    i.verify(new Script(), new Script().add(Opcode.OP_1), new Transaction(), 0, POST, new BN(0))
      .should.equal(true)
  })
})
