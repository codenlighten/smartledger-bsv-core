'use strict'

/**
 * Shared harness for the SV Node script vectors in test/data/bitcoin-sv.
 *
 * Adapted from @smartledger/bsv tools/sv-vector-harness.js (the JavaScript library this package
 * ports), so the two report the same corpus through the same logic and their
 * figures can be compared line for line. In this package it REPORTS and does not
 * gate: the numbers are expected to move while the port reaches parity with the
 * node, after which it becomes a gate. Build first (`npm run build`); it measures
 * dist/, which is what ships.
 *
 * These are the reference node's own test data, copied verbatim, and they are
 * the specification this interpreter is measured against. The corpus in
 * test/data/bitcoind is Bitcoin Core's and encodes rules BSV abandoned at
 * Genesis in 2020; it is not a consensus reference for this package.
 *
 * Used by tools/sv-vector-report.js. When a gate is added under test/, it should
 * call runAll() here too, so the progress report and the gate cannot disagree
 * about what passes.
 *
 * On eras. The node decides most rules by the era of the *output being spent*,
 * carried in SCRIPT_UTXO_AFTER_GENESIS and SCRIPT_UTXO_AFTER_CHRONICLE, and a
 * few by the era of the *spending transaction*, carried in SCRIPT_GENESIS and
 * SCRIPT_CHRONICLE.
 *
 * Era flags are passed through as the node's own, which is what the rows name.
 */

// The library under test. This package's own build by default; use() points the
// harness at another implementation with the same API (tools/sv-vector-delta.js
// passes @smartledger/bsv), so both are scored by identical code.
let Script, Opcode, Interpreter, Transaction, BN, BufferWriter, OPCODE_BASELINE

function use (bsv) {
  Script = bsv.Script
  Opcode = bsv.Opcode
  Interpreter = bsv.Script.Interpreter
  Transaction = bsv.Transaction
  BN = bsv.crypto.BN
  BufferWriter = bsv.encoding.BufferWriter
  OPCODE_BASELINE =
    Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES | Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES
}
use(require('../dist/index.js'))

const rawVectors = require('../test/data/bitcoin-sv/script_tests.json')

// Mapped by name rather than by value. The bit values agree with the node's
// today, but this package once put MONOLITH and MAGNETIC on 1<<18 and 1<<19 —
// the node's SCRIPT_GENESIS and SCRIPT_UTXO_AFTER_GENESIS — and a value mapping
// would have run every vector under the wrong rules while appearing to pass.
const FLAG_MAP = {
  NONE: 'SCRIPT_VERIFY_NONE',
  P2SH: 'SCRIPT_VERIFY_P2SH',
  STRICTENC: 'SCRIPT_VERIFY_STRICTENC',
  DERSIG: 'SCRIPT_VERIFY_DERSIG',
  LOW_S: 'SCRIPT_VERIFY_LOW_S',
  NULLDUMMY: 'SCRIPT_VERIFY_NULLDUMMY',
  SIGPUSHONLY: 'SCRIPT_VERIFY_SIGPUSHONLY',
  MINIMALDATA: 'SCRIPT_VERIFY_MINIMALDATA',
  DISCOURAGE_UPGRADABLE_NOPS: 'SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS',
  CLEANSTACK: 'SCRIPT_VERIFY_CLEANSTACK',
  CHECKLOCKTIMEVERIFY: 'SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY',
  CHECKSEQUENCEVERIFY: 'SCRIPT_VERIFY_CHECKSEQUENCEVERIFY',
  MINIMALIF: 'SCRIPT_VERIFY_MINIMALIF',
  NULLFAIL: 'SCRIPT_VERIFY_NULLFAIL',
  COMPRESSED_PUBKEYTYPE: 'SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE',
  SIGHASH_FORKID: 'SCRIPT_ENABLE_SIGHASH_FORKID',
  REPLAY_PROTECTION: 'SCRIPT_ENABLE_REPLAY_PROTECTION',
  MONOLITH_OPCODES: 'SCRIPT_ENABLE_MONOLITH_OPCODES',
  MAGNETIC_OPCODES: 'SCRIPT_ENABLE_MAGNETIC_OPCODES'
}

// OPCODE_BASELINE, set in use(). The corpus never names MONOLITH or MAGNETIC,
// because the node has no such flags — those opcodes were restored on BSV in
// 2018 and are simply enabled (IsOpcodeDisabled in the node's interpreter.cpp
// disables only 2MUL and 2DIV, and only before Chronicle). This package still gates them, so by default they
// are enabled for every row, as the library's harness does, keeping the two
// reports comparable. `runAll({ nodeFlagsOnly: true })` (report flag
// --node-flags-only) drops that allowance and shows the gating itself: 66 rows
// (MUL, LSHIFT, RSHIFT, INVERT) as measured on 2026-09-29.

/**
 * Result codes this library reports more narrowly than the node does, and the
 * node code each stands for.
 *
 * Matching the node's accept/reject outcome is not the same as failing for the
 * node's reason, and the gap between the two hid real bugs: a div-by-zero
 * guard comparing a BN against the number 0, so that it never fired and bn.js
 * asserted instead; script number decoding throwing past the evaluator into a
 * generic catch; a truncated PUSHDATA doing the same. All three left the
 * script failing, just not in the way the node fails it, so the outcome check
 * stayed green through every one.
 *
 * This is a short statement of intent rather than a list of exempted vectors,
 * and it ratchets both ways — an unlisted mismatch fails, and so does an alias
 * no vector produces any more. Anything added here should be a name that says
 * *more* than the node's, never a different failure wearing its label.
 */
const ERROR_CODE_ALIASES = {
  EVAL_FALSE_IN_STACK: 'EVAL_FALSE',
  EVAL_FALSE_NO_RESULT: 'EVAL_FALSE',
  EVAL_FALSE_NO_P2SH_STACK: 'EVAL_FALSE',
  EVAL_FALSE_IN_P2SH_STACK: 'EVAL_FALSE',
  SIG_DER_INVALID_FORMAT: 'SIG_DER',
  SIG_DER_HIGH_S: 'SIG_HIGH_S',
  INVALID_OPERAND_SIZE: 'OPERAND_SIZE',
  INVALID_SPLIT_RANGE: 'SPLIT_RANGE'
}

/** The bare result code, without the prefix or any appended detail. */
function errorCode (errstr) {
  return String(errstr || '').replace(/^SCRIPT_ERR_/, '').split(':')[0].trim()
}

/** Does what we reported match the node's `expected` code, or alias to it? */
function errorCodeMatches (expected, errstr) {
  const got = errorCode(errstr)
  return got === expected || ERROR_CODE_ALIASES[got] === expected
}

/** Parse a bitcoind-format script string, e.g. "0x47 0x3044... CHECKSIG". */
function fromBitcoindString (str) {
  const bw = new BufferWriter()
  for (const token of String(str).split(' ')) {
    if (token === '') continue
    if (token[0] === '0' && token[1] === 'x') {
      bw.write(Buffer.from(token.slice(2), 'hex'))
    } else if (token[0] === "'") {
      bw.write(Script().add(Buffer.from(token.slice(1, token.length - 1))).toBuffer())
    } else if (typeof Opcode['OP_' + token] !== 'undefined') {
      bw.writeUInt8(Opcode['OP_' + token])
    } else if (typeof Opcode[token] === 'number') {
      bw.writeUInt8(Opcode[token])
    } else if (!isNaN(parseInt(token))) {
      bw.write(Script().add(new BN(token).toScriptNumBuffer()).toBuffer())
    } else {
      const err = new Error('unknown script token: ' + token)
      err.token = token
      throw err
    }
  }
  return Script.fromBuffer(bw.concat())
}

/**
 * Row layout, from script_json_test in the node's src/test/script_tests.cpp:
 *
 *   [ [nValue]?, txnVersion, scriptSig, scriptPubKey, flags, expected, comment? ]
 *
 * nValue appears only where a row needs an amount and is array-wrapped in
 * whole coins. txnVersion is the spending transaction's version, which
 * Chronicle uses to gate its malleability relaxations — it is not padding and
 * it is not an amount.
 */
function parseRow (row) {
  let pos = 0
  let value = 0
  if (Array.isArray(row[0])) {
    value = Math.round(parseFloat(row[0][0]) * 1e8)
    pos++
  }
  if (row.length < 4 + pos) return null
  return {
    version: parseInt(row[pos], 10),
    scriptSig: row[pos + 1],
    scriptPubKey: row[pos + 2],
    flagStr: row[pos + 3],
    expected: row[pos + 4],
    satoshis: value,
    comment: row.slice(pos + 5).join(' ')
  }
}

function classifyFlags (flagStr, nodeFlagsOnly) {
  let flags = nodeFlagsOnly ? 0 : OPCODE_BASELINE
  const unknown = []
  for (const raw of String(flagStr).split(',')) {
    const name = raw.trim()
    if (!name) continue
    if (FLAG_MAP[name] !== undefined) {
      flags |= Interpreter[FLAG_MAP[name]]
    } else if (name === 'GENESIS') {
      flags |= Interpreter.SCRIPT_GENESIS
    } else if (name === 'UTXO_AFTER_GENESIS') {
      flags |= Interpreter.SCRIPT_UTXO_AFTER_GENESIS
    } else if (name === 'UTXO_AFTER_CHRONICLE') {
      flags |= Interpreter.SCRIPT_UTXO_AFTER_CHRONICLE
    } else {
      unknown.push(name)
    }
  }
  return { flags, unknown }
}

/**
 * Build and verify the crediting/spending transaction pair, mirroring
 * BuildCreditingTransaction and BuildSpendingTransaction in the node's
 * src/test/script_tests.cpp. The crediting transaction is always version 1;
 * only the spending transaction carries the version under test.
 */
function evaluate (row, flags) {
  // DoTest's one flag adjustment, which the rows themselves do not state:
  //
  //   if(flags & SCRIPT_VERIFY_CLEANSTACK) flags |= SCRIPT_VERIFY_P2SH;
  //
  // Without it a row naming CLEANSTACK alone is verified under a flag set the node refuses
  // outright, so it fails for the wrong reason and the row silently stops testing clean
  // stacks at all.
  if ((flags & Interpreter.SCRIPT_VERIFY_CLEANSTACK) !== 0) {
    flags |= Interpreter.SCRIPT_VERIFY_P2SH
  }

  const scriptSig = fromBitcoindString(row.scriptSig)
  const scriptPubKey = fromBitcoindString(row.scriptPubKey)

  const credtx = new Transaction()
  credtx.version = 1
  credtx.nLockTime = 0
  credtx.uncheckedAddInput(new Transaction.Input({
    prevTxId: '0'.repeat(64),
    outputIndex: 0xffffffff,
    sequenceNumber: 0xffffffff,
    script: Script('OP_0 OP_0')
  }))
  credtx.addOutput(new Transaction.Output({ script: scriptPubKey, satoshis: row.satoshis }))

  const spendtx = new Transaction()
  spendtx.version = row.version
  spendtx.nLockTime = 0
  spendtx.uncheckedAddInput(new Transaction.Input({
    prevTxId: credtx.id.toString('hex'),
    outputIndex: 0,
    sequenceNumber: 0xffffffff,
    script: scriptSig
  }))
  spendtx.addOutput(new Transaction.Output({ script: Script(), satoshis: row.satoshis }))

  const interp = new Interpreter()
  const ok = interp.verify(scriptSig, scriptPubKey, spendtx, 0, flags, new BN(row.satoshis))
  return { ok, errstr: interp.errstr }
}

/** A stable id for a row, so a known-failure list survives reordering. */
function vectorId (raw) {
  return require('crypto').createHash('sha256')
    .update(JSON.stringify(raw)).digest('hex').slice(0, 12)
}

/**
 * Run every vector. Each result is
 *
 *   { index, id, row, passed, reason, direction, gotErrstr }
 *
 * `index` is the row's position in script_tests.json (0-based, counting the
 * comment rows), so `jq '.[index]'` finds it.
 *
 * `direction` is 'accept' where this library accepted a script the node
 * rejects — the direction that can cost money — and 'reject' for the converse.
 */
function runAll (opts) {
  const nodeFlagsOnly = Boolean(opts && opts.nodeFlagsOnly)
  const results = []
  rawVectors.forEach(function (raw, index) {
    if (!Array.isArray(raw) || raw.length < 4) return
    const row = parseRow(raw)
    if (row === null) return

    const cls = classifyFlags(row.flagStr, nodeFlagsOnly)
    const expectOk = row.expected === 'OK'

    let got = null
    let thrown = null
    try {
      got = evaluate(row, cls.flags)
    } catch (e) {
      thrown = e
    }

    let reason = null
    let direction = null
    if (thrown !== null) {
      reason = 'threw: ' + String(thrown.message).slice(0, 70)
      direction = 'reject'
    } else if (got.ok !== expectOk) {
      if (expectOk) {
        reason = 'expected OK, rejected with ' + got.errstr
        direction = 'reject'
      } else {
        reason = 'expected ' + row.expected + ', but ACCEPTED'
        direction = 'accept'
      }
    }

    // Only meaningful where the node rejects and so does this library: there
    // is no code to compare on a row the node accepts, and a row whose outcome
    // already disagrees is reported as that rather than twice.
    const comparable = !expectOk && reason === null
    results.push({
      index,
      id: vectorId(raw),
      row,
      unknownFlags: cls.unknown,
      gotErrstr: got ? got.errstr : null,
      passed: reason === null,
      reason,
      direction,
      expectedCode: comparable ? row.expected : null,
      gotCode: comparable ? errorCode(got.errstr) : null,
      codeMatches: comparable ? errorCodeMatches(row.expected, got.errstr) : null
    })
  })
  return results
}

/** A one-line description of a row, for failure output. */
function describe (row) {
  return String(row.scriptSig).slice(0, 40) + ' | ' +
    String(row.scriptPubKey).slice(0, 40) +
    '  [' + row.flagStr + ']' +
    (row.comment ? '  // ' + row.comment.slice(0, 50) : '')
}

module.exports = {
  use,
  runAll,
  evaluate,
  describe,
  parseRow,
  vectorId,
  classifyFlags,
  fromBitcoindString,
  errorCode,
  errorCodeMatches,
  ERROR_CODE_ALIASES,
  FLAG_MAP
}
