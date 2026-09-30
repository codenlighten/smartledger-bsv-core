'use strict'

/**
 * Shared harness for the SV Node transaction digest vectors in
 * test/data/bitcoin-sv/sighash.json.
 *
 * Ported from @smartledger/bsv, which carries the same corpus and harness, so the
 * two implementations are measured by the same yardstick rather than each by its own
 * recorded behaviour. Used by test/consensus/sv-sighash-vectors.js.
 *
 * Row layout, from sighash_tests.cpp in the node:
 *
 *   [ raw_transaction, script, input_index, hashType,
 *     signature_hash (regular), signature_hash (no forkid) ]
 *
 * Two columns pin the routing in SignatureHash() rather than one branch of it.
 * The node takes BIP143 only when forkid is enabled AND requested AND the
 * signature has not asked for the original algorithm:
 *
 *   if(enabledSighashForkid && sigHashType.hasForkId() && !sigHashType.hasChronicle())
 *       return SignatureHashBIP143(...);
 *   return SignatureHashOriginal(...);
 *
 * Note where the Chronicle bit is NOT consulted: the node does not ask whether
 * Chronicle is enabled before honouring it. That gating lives in
 * CheckSignatureEncoding, which rejects a signature carrying the bit outside
 * Chronicle as SCRIPT_ERR_ILLEGAL_CHRONICLE — so such a signature never
 * reaches a digest at all. For a row whose hash type sets 0x20 both columns
 * are therefore identical, the original algorithm being taken either way, and
 * that is what makes carrying both columns worth the trouble.
 */

const bsv = require('..')
const Script = bsv.Script
const BN = bsv.crypto.BN
const Transaction = bsv.Transaction
const Signature = bsv.crypto.Signature
const Interpreter = bsv.Script.Interpreter
const sighash = Transaction.Sighash

const rawVectors = require('../test/data/bitcoin-sv/sighash.json')

const FORKID = Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID
const zeroBN = BN.Zero

/** The first row of the corpus names the columns rather than carrying data. */
function rows () {
  return rawVectors.slice(1).filter(v => Array.isArray(v) && v.length >= 6)
}

/**
 * Which digest the node produces for this hash type, under each flag setting.
 * Named rather than inferred, so a routing regression reports as one.
 */
function algorithm (nhashtype, forkidEnabled) {
  const t = nhashtype >>> 0
  const bip143 = forkidEnabled &&
    (t & Signature.SIGHASH_FORKID) !== 0 &&
    (t & Signature.SIGHASH_CHRONICLE) === 0
  return bip143 ? 'BIP143' : 'OTDA'
}

/**
 * Run every vector. Each result is
 *
 *   { index, hashType, chronicleBit, algorithm, passed, reason }
 *
 * where `algorithm` is the one the node's routing selects with forkid enabled.
 */
function runAll () {
  return rows().map(function (vector, i) {
    const nhashtype = vector[3]
    const chronicleBit = ((nhashtype >>> 0) & Signature.SIGHASH_CHRONICLE) !== 0

    const base = {
      index: i + 1,
      hashType: nhashtype,
      chronicleBit,
      algorithm: algorithm(nhashtype, true)
    }

    // A fresh Script per call: the original algorithm removes code separators
    // in place, so sharing one would let the first call change what the second
    // is given.
    function digest (flags) {
      const tx = new Transaction(Buffer.from(vector[0], 'hex'))
      return sighash.sighash(tx, nhashtype, vector[2],
        Script(Buffer.from(vector[1], 'hex')), zeroBN, flags).toString('hex')
    }

    let regular, noForkId
    try {
      regular = digest(FORKID)
      noForkId = digest(0)
    } catch (e) {
      return Object.assign(base, {
        passed: false,
        reason: 'threw: ' + String(e.message).slice(0, 70)
      })
    }

    if (regular !== vector[4]) {
      return Object.assign(base, {
        passed: false,
        reason: 'regular column: ' + regular + ' != ' + vector[4]
      })
    }
    if (noForkId !== vector[5]) {
      return Object.assign(base, {
        passed: false,
        reason: 'no-forkid column: ' + noForkId + ' != ' + vector[5]
      })
    }
    return Object.assign(base, { passed: true, reason: null })
  })
}

/** Rows whose two columns must agree, because the Chronicle bit is set. */
function chronicleRows () {
  return rows().filter(v => ((v[3] >>> 0) & Signature.SIGHASH_CHRONICLE) !== 0)
}

module.exports = { runAll, rows, chronicleRows, algorithm }
