'use strict'

const path = require('path')

// Bitcoin Core's script evaluation vectors, as shipped with this repo.
// Row format: [scriptSig, scriptPubKey, flags, expectedError, comment]
// (Rows may be prefixed by a witness/amount array in newer formats; rows that
// are a single string are section comments.)
const RAW = require(path.join(__dirname, '..', '..', 'test', 'data', 'bitcoind', 'script_tests.json'))
const VECTORS = RAW.filter((v) => Array.isArray(v) && v.length >= 4)

const { scriptFromBitcoindString, runScriptTest, flagsFromString } = require('../lib/bitcoind')

const FLAG_NAMES = [
  'NONE', 'P2SH', 'STRICTENC', 'DERSIG', 'LOW_S', 'NULLDUMMY', 'SIGPUSHONLY',
  'MINIMALDATA', 'DISCOURAGE_UPGRADABLE_NOPS', 'CLEANSTACK',
  'CHECKLOCKTIMEVERIFY', 'CHECKSEQUENCEVERIFY', 'MINIMALIF', 'NULLFAIL'
]

const getFlags = flagsFromString

const cases = {
  // The full Bitcoin Core script corpus, evaluated against a real credit/spend
  // transaction pair. Each row records the verdict AND the expected result from
  // the vector file, so the fixture shows agreement or disagreement directly.
  'bitcoind script_tests (all)': (bsv) => {
    return VECTORS.map((v, i) => {
      // Newer-format rows lead with an array of witness data + amount.
      const offset = Array.isArray(v[0]) ? 1 : 0
      const amount = offset ? Math.round((v[0][v[0].length - 1] || 0) * 1e8) : 0
      const [sigStr, pubStr, flagStr, expected] = v.slice(offset, offset + 4)
      try {
        const scriptSig = scriptFromBitcoindString(bsv, sigStr)
        const scriptPubkey = scriptFromBitcoindString(bsv, pubStr)
        const { verified } = runScriptTest(bsv, scriptSig, scriptPubkey, getFlags(bsv, flagStr), amount)
        // Core writes "OK" for scripts that must verify, an error name otherwise.
        const shouldPass = expected === 'OK'
        return `${i}:${verified ? 'pass' : 'fail'}:${verified === shouldPass ? 'agrees' : 'DISAGREES'}:${expected}`
      } catch (err) {
        return `${i}:threw:${err.name}:${expected}`
      }
    })
  },

  'bitcoind script_tests count': () => VECTORS.length,

  // BSV deliberately diverges from Bitcoin Core on a small, known set of
  // vectors: the opcodes Core disabled (CAT, SPLIT, NUM2BIN, BIN2NUM, AND, OR,
  // XOR, DIV, MOD) are restored in BSV, and 0xba is no longer the first
  // undefined opcode. Everything else must agree.
  //
  // Pinning the divergence set — not just the agreement count — means that
  // enabling or disabling an opcode by accident shows up as a diff instead of
  // hiding inside a summary number.
  'bitcoind script_tests: divergence from Core is exactly the known set': (bsv) => {
    const diverging = []
    VECTORS.forEach((v, i) => {
      const offset = Array.isArray(v[0]) ? 1 : 0
      const amount = offset ? Math.round((v[0][v[0].length - 1] || 0) * 1e8) : 0
      const [sigStr, pubStr, flagStr, expected, comment] = v.slice(offset, offset + 5)
      try {
        const { verified } = runScriptTest(
          bsv,
          scriptFromBitcoindString(bsv, sigStr),
          scriptFromBitcoindString(bsv, pubStr),
          getFlags(bsv, flagStr),
          amount
        )
        if (verified !== (expected === 'OK')) {
          diverging.push(`${i}:${expected}:${comment || ''}`)
        }
      } catch (err) {
        diverging.push(`${i}:threw:${err.name}`)
      }
    })
    return { count: diverging.length, cases: diverging }
  },

  // --- Interpreter limits ---------------------------------------------------
  // These constants are consensus parameters. A rewrite that changes one
  // changes which transactions are valid.
  'interpreter limit constants': (bsv) => {
    const I = bsv.Script.Interpreter
    return {
      MAX_SCRIPT_ELEMENT_SIZE: I.MAX_SCRIPT_ELEMENT_SIZE,
      MAXIMUM_ELEMENT_SIZE: I.MAXIMUM_ELEMENT_SIZE,
      MAX_OPS_PER_SCRIPT: I.MAX_OPS_PER_SCRIPT,
      MAX_SCRIPT_SIZE: I.MAX_SCRIPT_SIZE,
      LOCKTIME_THRESHOLD: I.LOCKTIME_THRESHOLD
    }
  },
  'interpreter default limits': (bsv) => bsv.Script.Interpreter.getLimits(),
  'interpreter genesis limits': (bsv) => {
    const I = bsv.Script.Interpreter
    const before = I.getLimits()
    I.useGenesisLimits()
    const after = I.getLimits()
    I.setLimits(before) // restore; suites must not leak global state
    return { before, after, restored: I.getLimits() }
  },

  // --- All verify flags exposed --------------------------------------------
  'verify flag values': (bsv) => {
    const I = bsv.Script.Interpreter
    const out = {}
    for (const k of Object.keys(I)) {
      if (k.startsWith('SCRIPT_VERIFY_') || k.startsWith('SCRIPT_ENABLE_') || k.startsWith('SEQUENCE_')) {
        out[k] = I[k]
      }
    }
    return out
  },
  'named flag parsing': (bsv) => FLAG_NAMES.map((n) => ({ name: n, value: getFlags(bsv, n) })),

  // --- Direct evaluation ----------------------------------------------------
  'evaluate 1 ADD': (bsv) => {
    const i = new bsv.Script.Interpreter()
    const ok = i.verify(bsv.Script.fromASM('OP_1 OP_2'), bsv.Script.fromASM('OP_ADD OP_3 OP_EQUAL'))
    return { ok, errstr: i.errstr }
  },
  'evaluate false result': (bsv) => {
    const i = new bsv.Script.Interpreter()
    const ok = i.verify(bsv.Script.fromASM('OP_1 OP_2'), bsv.Script.fromASM('OP_ADD OP_4 OP_EQUAL'))
    return { ok, errstr: i.errstr }
  },
  'evaluate empty scripts': (bsv) => {
    const i = new bsv.Script.Interpreter()
    return { ok: i.verify(bsv.Script.empty(), bsv.Script.empty()), errstr: i.errstr }
  },
  'evaluate OP_RETURN halts': (bsv) => {
    const i = new bsv.Script.Interpreter()
    return { ok: i.verify(bsv.Script.empty(), bsv.Script.fromASM('OP_RETURN')), errstr: i.errstr }
  },
  'evaluate disabled opcode': (bsv) => {
    const i = new bsv.Script.Interpreter()
    return { ok: i.verify(bsv.Script.fromASM('OP_1 OP_2'), bsv.Script.fromASM('OP_2MUL')), errstr: i.errstr }
  },

  // --- Minimal encoding helpers --------------------------------------------
  'castToBool cases': (bsv) => {
    const I = bsv.Script.Interpreter
    return ['', '00', '01', '80', '0080', 'ff', '0000000000'].map((h) => ({
      hex: h, bool: I.castToBool(Buffer.from(h, 'hex'))
    }))
  },
  'minimallyEncode cases': (bsv) => {
    const I = bsv.Script.Interpreter
    return ['', '00', '0000', '0100', '80', '0080', 'ff00', '01'].map((h) => ({
      hex: h,
      isMinimal: I._isMinimallyEncoded(Buffer.from(h, 'hex')),
      encoded: I._minimallyEncode(Buffer.from(h, 'hex')).toString('hex')
    }))
  }
}

module.exports = { name: 'interpreter', cases }
