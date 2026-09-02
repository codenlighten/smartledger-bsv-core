'use strict'

/* global describe, it, beforeEach, afterEach */
require('chai').should()
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter
const Script = bsv.Script
const Opcode = bsv.Opcode
const Transaction = bsv.Transaction

// The node decides almost every limit by the era of the OUTPUT BEING SPENT, not by
// a process-wide setting, because an output made before an upgrade is spent under
// the old rules forever. These cover the flags that carry that, and the three
// signature-encoding rules BSV enforces as consensus rather than standardness.
describe('Interpreter era and mandatory-rule flags', function () {
  let saved

  beforeEach(function () { saved = Interpreter.getLimits() })
  afterEach(function () { Interpreter.setLimits(saved) })

  // The bit positions are part of the interface, not an implementation detail: a
  // flag word crosses the boundary to @smartledger/bsv and to node-derived
  // vectors, so a collision here would silently mean something else. MONOLITH and
  // MAGNETIC sat on 18 and 19 — where the era flags now live — until this change.
  describe('bit assignments', function () {
    const BITS = {
      SCRIPT_ENABLE_MONOLITH_OPCODES: 11,
      SCRIPT_ENABLE_MAGNETIC_OPCODES: 12,
      SCRIPT_GENESIS: 18,
      SCRIPT_UTXO_AFTER_GENESIS: 19,
      SCRIPT_ENABLE_CHRONICLE: 20,
      SCRIPT_UTXO_AFTER_CHRONICLE: 21
    }

    Object.keys(BITS).forEach(function (name) {
      it(name + ' is bit ' + BITS[name], function () {
        Interpreter[name].should.equal(1 << BITS[name])
      })
    })

    it('assigns every flag a distinct bit', function () {
      const names = Object.keys(Interpreter).filter(function (k) {
        return /^SCRIPT_(VERIFY|ENABLE|GENESIS|UTXO|CHRONICLE)/.test(k) &&
          typeof Interpreter[k] === 'number' && Interpreter[k] !== 0
      })
      const seen = new Map()
      names.forEach(function (n) {
        const v = Interpreter[n]
        // SCRIPT_CHRONICLE is a documented alias for SCRIPT_ENABLE_CHRONICLE.
        const alias = (n === 'SCRIPT_CHRONICLE' || seen.get(v) === 'SCRIPT_CHRONICLE')
        if (seen.has(v) && !alias) {
          throw new Error(n + ' collides with ' + seen.get(v) + ' on bit value ' + v)
        }
        seen.set(v, n)
      })
      names.length.should.be.above(15)
    })
  })

  describe('era predicates', function () {
    function interp (flags) {
      const i = new Interpreter()
      i.set({ flags })
      return i
    }

    it('reads Genesis from the UTXO flag, not from SCRIPT_GENESIS', function () {
      interp(Interpreter.SCRIPT_UTXO_AFTER_GENESIS).isAfterGenesis().should.equal(true)
      // SCRIPT_GENESIS describes the BLOCK the spending transaction is in, which is
      // not what the limits key off.
      interp(Interpreter.SCRIPT_GENESIS).isAfterGenesis().should.equal(false)
      interp(0).isAfterGenesis().should.equal(false)
    })

    it('accepts either Chronicle flag', function () {
      interp(Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE).isAfterChronicle().should.equal(true)
      interp(Interpreter.SCRIPT_ENABLE_CHRONICLE).isAfterChronicle().should.equal(true)
      interp(0).isAfterChronicle().should.equal(false)
    })

    it('derives the script-number width from the era, not from the static', function () {
      interp(0).maxScriptNumLength().should.equal(4)
      interp(Interpreter.SCRIPT_UTXO_AFTER_GENESIS).maxScriptNumLength().should.equal(750000)
      interp(Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE).maxScriptNumLength().should.equal(32000000)
      // Chronicle wins when both are set, as it does in the node.
      interp(Interpreter.SCRIPT_UTXO_AFTER_GENESIS | Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE)
        .maxScriptNumLength().should.equal(32000000)
    })

    it('derives the removed caps from the era too', function () {
      const pre = interp(0)
      const post = interp(Interpreter.SCRIPT_UTXO_AFTER_GENESIS)
      pre.maxScriptElementSize().should.equal(520)
      pre.maxScriptSize().should.equal(10000)
      pre.maxOpsPerScript().should.equal(201)
      pre.maxPubKeysPerMultisig().should.equal(20)
      post.maxScriptElementSize().should.equal(Interpreter.UNLIMITED)
      post.maxScriptSize().should.equal(Interpreter.UNLIMITED)
      post.maxOpsPerScript().should.equal(Interpreter.UNLIMITED)
      post.maxPubKeysPerMultisig().should.equal(4294967295)
    })

    // Before Genesis the mere PRESENCE of a disabled opcode invalidates the script,
    // even in a branch that never runs. After it, only executing one fails.
    it('only fails an unexecuted disabled opcode before Genesis', function () {
      // OP_2MUL is disabled until Chronicle, and this branch never executes.
      const lock = new Script()
        .add(Opcode.OP_0).add(Opcode.OP_IF).add(Opcode.OP_2MUL).add(Opcode.OP_ENDIF)
        .add(Opcode.OP_1)
      function run (flags) {
        const i = new Interpreter()
        const ok = i.verify(new Script(), lock, new Transaction(), 0, flags)
        return ok ? 'ACCEPT' : i.errstr
      }
      run(0).should.equal('SCRIPT_ERR_DISABLED_OPCODE')
      run(Interpreter.SCRIPT_UTXO_AFTER_GENESIS).should.equal('ACCEPT')
    })
  })

  // OP_BIN2NUM range-checked its result against a bare _isMinimallyEncoded(buf),
  // whose nMaxNumSize argument defaults to MAXIMUM_ELEMENT_SIZE (4), so every era
  // got the pre-Genesis width. Any unsigned field whose top byte has the sign bit
  // set needs a fifth byte to stay positive — an 8-byte satoshi amount at or above
  // 2^31 (21.47 BSV), and an nLockTime at or above 0x80000000 (19 Jan 2038).
  describe('OP_BIN2NUM honours the era script-number width', function () {
    function bin2num (hex, flags) {
      const i = new Interpreter()
      const ok = i.verify(new Script().add(Buffer.from(hex, 'hex')),
        new Script().add(Opcode.OP_BIN2NUM), new Transaction(), 0, flags)
      return ok ? 'ACCEPT' : i.errstr
    }
    const amount25BSV = '00f9029500000000' // 2,500,000,000 satoshis, unsigned LE
    const lockTime2038 = '0000008000' // 2147483648, sign-padded to five bytes

    it('rejects a 5-byte result before Genesis, where 4 is the real cap', function () {
      bin2num(amount25BSV, 0).should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
      bin2num(lockTime2038, 0).should.equal('SCRIPT_ERR_INVALID_NUMBER_RANGE')
    })

    it('accepts it once the era says the width is wider', function () {
      bin2num(amount25BSV, Interpreter.SCRIPT_UTXO_AFTER_GENESIS).should.equal('ACCEPT')
      bin2num(lockTime2038, Interpreter.SCRIPT_UTXO_AFTER_GENESIS).should.equal('ACCEPT')
    })
  })

  // There are two op-count checks. The one in step() is era-derived; the one inside
  // OP_CHECKMULTISIG, which adds the key count, kept reading the static — so the
  // line allowing up to UINT32_MAX keys after Genesis was immediately followed by
  // one refusing them against a cap the era had removed. No vector can catch that:
  // every OP_COUNT vector in the corpus is pre-Genesis, where the two agree.
  // Reported upstream as smartledger-bsv#155 and fixed in both.
  describe('the CHECKMULTISIG op count is the era\'s, not the static', function () {
    const POST = Interpreter.SCRIPT_UTXO_AFTER_GENESIS | Interpreter.SCRIPT_GENESIS

    // 0-of-N: <dummy> <m=0> then N keys and N. No signature is checked, which is
    // what isolates the two COUNT rules from everything else CHECKMULTISIG does.
    function multisig (nKeys, nops, flags) {
      const key = bsv.PrivateKey.fromRandom().toPublicKey().toBuffer()
      const unlock = new Script().add(Opcode.OP_0).add(Opcode.OP_0)
      const lock = new Script()
      for (let j = 0; j < nops; j++) lock.add(Opcode.OP_NOP)
      for (let k = 0; k < nKeys; k++) lock.add(key)
      lock.add(new bsv.crypto.BN(nKeys).toScriptNumBuffer()).add(Opcode.OP_CHECKMULTISIG)
      const i = new Interpreter()
      const ok = i.verify(unlock, lock, new Transaction(), 0, flags)
      return ok ? 'ACCEPT' : i.errstr
    }

    it('accepts more keys after Genesis than the pre-Genesis cap allowed', function () {
      // 600 keys is 20,404 bytes and 601 opcodes — over the pre-Genesis 20-key,
      // 201-op and 10,000-byte caps, all three of which Genesis removed or raised.
      multisig(600, 0, POST).should.equal('ACCEPT')
    })

    it('still enforces the op count before Genesis', function () {
      // 190 NOPs + 20 keys + CHECKMULTISIG = 211 ops against this repo's
      // pre-Genesis limit of 201, in well under the 10,000-byte size cap, so the
      // size cap cannot be what rejects it.
      multisig(20, 190, 0).should.equal('SCRIPT_ERR_OP_COUNT')
      multisig(20, 0, 0).should.equal('ACCEPT')
    })

    it('still enforces the pre-Genesis 20-key cap', function () {
      multisig(21, 0, 0).should.equal('SCRIPT_ERR_PUBKEY_COUNT')
    })

    it('lifts the op count after Genesis, not just the key count', function () {
      multisig(20, 190, POST).should.equal('ACCEPT')
    })
  })

  // BSV enforces these three as MANDATORY, not as standardness. Each was broadcast
  // to mainnet in a transaction violating it and nothing else, and the node
  // answered code 16 `mandatory-script-verify-flag-failed` — as against code 64
  // `non-mandatory-script-verify-flag`, which it returns for MINIMALDATA,
  // CLEANSTACK, NULLDUMMY and the upgradable NOPs.
  describe('mandatory signature-encoding rules', function () {
    const MANDATORY = ['SCRIPT_VERIFY_SIGPUSHONLY', 'SCRIPT_VERIFY_LOW_S', 'SCRIPT_VERIFY_NULLFAIL']

    MANDATORY.forEach(function (name) {
      it('currentConsensusFlags() includes ' + name, function () {
        (Interpreter.currentConsensusFlags() & Interpreter[name]).should.not.equal(0)
      })
      it('mainnetFlags() includes ' + name, function () {
        (Interpreter.mainnetFlags() & Interpreter[name]).should.not.equal(0)
      })
    })

    // The invariant behind those, stated once so a flag added to one helper and not
    // the other fails here rather than in someone's covenant. @smartledger/bsv
    // shipped for several versions with LOW_S and NULLFAIL in mainnetFlags() but not
    // in the default word, and the test meant to catch it named two of the three
    // rules and missed the third.
    //
    // One-directional on purpose: mainnetFlags() additionally carries P2SH, DERSIG
    // and MINIMALDATA, and MINIMALDATA measured as code 64, so it is relay policy.
    it('never enforces a rule by default that mainnetFlags() would let through', function () {
      const current = Interpreter.currentConsensusFlags()
      const mainnet = Interpreter.mainnetFlags()
      current.should.not.equal(0)
      ;(current & ~mainnet).should.equal(0,
        'currentConsensusFlags() has bits mainnetFlags() lacks: 0x' + (current & ~mainnet).toString(16))
    })

    it('carries the era flags, so a mainnet validator is not applying 2019 limits', function () {
      const mainnet = Interpreter.mainnetFlags()
      ;(mainnet & Interpreter.SCRIPT_GENESIS).should.not.equal(0)
      ;(mainnet & Interpreter.SCRIPT_UTXO_AFTER_GENESIS).should.not.equal(0)
      ;(mainnet & Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE).should.not.equal(0)
      const i = new Interpreter()
      i.set({ flags: mainnet })
      i.maxScriptNumLength().should.equal(32000000)
      // afterChronicle: false is a pre-activation UTXO, still post-Genesis.
      const j = new Interpreter()
      j.set({ flags: Interpreter.mainnetFlags({ afterChronicle: false }) })
      j.maxScriptNumLength().should.equal(750000)
    })

    it('refuses a non-push unlocking script under both helpers', function () {
      const nonPush = new Script('OP_1 OP_2 OP_ADD')
      const lock = new Script('OP_3 OP_EQUAL')
      const a = new Interpreter()
      a.verify(nonPush, lock, new Transaction(), 0,
        Interpreter.currentConsensusFlags() & ~Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)
      a.errstr.should.equal('SCRIPT_ERR_SIG_PUSHONLY')
      const b = new Interpreter()
      b.verify(nonPush, lock, new Transaction(), 0,
        Interpreter.mainnetFlags() & ~Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)
      b.errstr.should.equal('SCRIPT_ERR_SIG_PUSHONLY')
    })
  })
})
