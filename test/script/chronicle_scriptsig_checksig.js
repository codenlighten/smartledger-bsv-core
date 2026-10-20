'use strict'

/* global describe, it */

// Post-Chronicle, a CHECKSIG or CHECKMULTISIG executing inside the UNLOCKING script signs
// everything from the most recent code separator to the end of that script PLUS the locking
// script. bitcoin-sv v1.2.3 `interpreter.cpp` 1475-1480 and 1571-1576:
//
//     // checksigData contains scriptPubKey if we are executing within a scriptSig
//     if(checksigData && IsChronicle(flags))
//         scriptCode += *checksigData;
//
// with `VerifyScript` passing `&scriptPubKey` for the scriptSig evaluation (2338) and
// `nullptr` for the scriptPubKey (2358) and P2SH-redeem (2402) evaluations.
//
// This port appended nothing, in any era, and measured 16 agree / 24 differ against the
// reference before the fix — the identical split to `@smartledger/bsv` before 9.44.0. The
// divergence ran in both directions: accepting spends the network rejects and rejecting
// spends it accepts.
//
// The gate is SCRIPT_CHRONICLE (1 << 20) alone, NOT the output-era bit
// SCRIPT_UTXO_AFTER_CHRONICLE (1 << 21). The relaxations gate on the output era, which is
// what took 571 of 24,568 disagreements to zero in core 1.3.0, so reaching for that helper
// here looks right and is wrong: a bit-21 gate passes all 24 rows of the first file and still
// disagrees on 16 of these 40.
//
// Data: oracle vectors in the BSV opcode lab repo, with reference verdicts from a compiled
// bitcoin-sv v1.2.3 oracle and an independent Rust node.

const assert = require('assert')
const fs = require('fs')
const path = require('path')
const bsv = require('../..')
const Interpreter = bsv.Interpreter || bsv.Script.Interpreter
const Script = bsv.Script
const Transaction = bsv.Transaction
const BN = bsv.BN || bsv.crypto.BN

const DIR = path.join(__dirname, '..', 'data', 'chronicle-scriptsig')
function load (f) {
  const m = {}
  fs.readFileSync(path.join(DIR, f), 'utf8').split('\n').filter(Boolean).forEach((l) => {
    const r = JSON.parse(l)
    m[r.id] = r
  })
  return m
}

// Flags are rebuilt from NAMES, never the vectors' `flagsHex`: the same flag set has
// different words in the two implementations, so a copied integer validates the wrong set.
function flagsFrom (names) {
  let f = 0
  names.forEach((n) => {
    assert.notStrictEqual(Interpreter[n], undefined, 'unmapped flag name: ' + n)
    f |= Interpreter[n]
  })
  return f
}

function run (row) {
  const it = new Interpreter()
  let ok
  try {
    ok = it.verify(
      Script.fromBuffer(Buffer.from(row.scriptSigHex, 'hex')),
      Script.fromBuffer(Buffer.from(row.scriptPubKeyHex, 'hex')),
      new Transaction(row.tx.hex), row.tx.nIn,
      flagsFrom(row.flagNames), new BN(row.tx.amountSats))
  } catch (e) { ok = false }
  return { ok, err: it.errstr || '' }
}

const SETS = [
  ['vectors-sighash-chronicle-scriptsig.jsonl', 'sighash-chronicle-scriptsig-reference-column.jsonl'],
  ['vectors-sighash-chronicle-scriptsig-era.jsonl', 'sighash-chronicle-scriptsig-era-reference-column.jsonl']
]

describe('Chronicle: a signature check inside the unlocking script', function () {
  SETS.forEach(function (pair) {
    describe(pair[0], function () {
      const vec = load(pair[0])
      const ref = load(pair[1])

      it('has a reference verdict for every vector', function () {
        const ids = Object.keys(vec)
        assert.ok(ids.length > 0)
        ids.forEach((id) => { assert.ok(ref[id], 'no reference verdict for ' + id) })
      })

      Object.keys(vec).forEach(function (id) {
        it('agrees with the reference on ' + id.split('/').slice(1).join('/'), function () {
          const expected = /^accept/i.test(String(ref[id].verdict))
          const got = run(vec[id])
          assert.strictEqual(got.ok, expected,
            'reference says ' + ref[id].verdict + ', we say ' +
            (got.ok ? 'accept' : 'reject (' + got.err + ')'))
        })
      })
    })
  })

  // The positive control, with no access to internals. Swapping bits 20 and 21 in the INPUT
  // flags is observationally identical to swapping which bit the gate reads, so a correct
  // bit-20 implementation fed swapped flags produces exactly the verdicts a bit-21-gated one
  // would produce on the real flags.
  it('separates a bit-20 gate from a bit-21 one', function () {
    const vec = load('vectors-sighash-chronicle-scriptsig-era.jsonl')
    const ref = load('sighash-chronicle-scriptsig-era-reference-column.jsonl')
    let differ = 0
    Object.keys(vec).forEach((id) => {
      const row = JSON.parse(JSON.stringify(vec[id]))
      const SWAP = {
        SCRIPT_CHRONICLE: 'SCRIPT_UTXO_AFTER_CHRONICLE',
        SCRIPT_UTXO_AFTER_CHRONICLE: 'SCRIPT_CHRONICLE'
      }
      row.flagNames = row.flagNames.map((n) => SWAP[n] || n)
      if (run(row).ok !== /^accept/i.test(String(ref[id].verdict))) differ++
    })
    assert.strictEqual(differ, 16,
      'a bit-21 gate must disagree with the reference on all 16 era rows; got ' + differ)
  })
})
