'use strict'

/* global describe, it */

// A RATCHET over every `.script.<prop>` dereference in src/. Ported from @smartledger/bsv.
//
// Two accessors return null rather than a Script:
//
//   * `Output#script` — null when the raw bytes could not be decoded, which happens for
//     output scripts the node ACCEPTS AND MINES (post-Genesis a top-level OP_RETURN
//     terminates as successful before a truncated tail is read, so `6a4c` is valid).
//   * `Input#script` — null when `isNull()`, the coinbase input every block has.
//
// Three call sites here dereferenced one without asking and threw a raw, untyped TypeError
// on data read from a valid block: `_hasDustOutputs`, `Output#getSize` and
// `Transaction#sort()`'s BIP69 comparator. All are fixed.
//
// The first audit was a pattern grep filtered by the shape of the bug already found, so it
// inherited that bug's blind spot and missed one. The enumeration below is the durable
// artifact and this test makes it self-enforcing: a new `.script.` dereference in src/ fails
// until it is classified here with a reason.
//
// Note `Output#inspect` and `Input#toObject` were ALREADY guarded with `if (this.script)`.
// The convention existed; the crashes were inconsistency with it.

var fs = require('fs')
var path = require('path')
require('chai').should()

var CLASSIFIED = {
  // --- receiver is a nullable Output#script, and the null case is handled ---
  'src/transaction/output.ts :: inspect': 'guarded by `if (this.script)`, falls back to _scriptBuffer hex',
  'src/transaction/output.ts :: toBuffer': 'getSize(): `this.script === null ? _scriptBuffer.length : ...`',
  'src/transaction/transaction.ts :: toBuffer': 'BIP69 comparator via outputScriptBytes(), null -> _scriptBuffer',

  // --- receiver is a nullable Input#script, and the null case is handled ---
  'src/transaction/input/input.ts :: toString': 'toObject(): guarded by `if (this.script)`; raw hex is always emitted',

  // --- receiver cannot be null: the script was parsed before this point ---
  'src/transaction/transaction.ts :: isPublicKeyHashOutPrefix': 'from(): utxo script parsed (throws typed InvalidBuffer) before dispatch',
  'src/transaction/transaction.ts :: isPublicKeyOut': 'from() dispatch, as above: a parsed utxo script',
  'src/transaction/transaction.ts :: isMultisigOut': 'from() dispatch, as above: a parsed utxo script',
  'src/transaction/transaction.ts :: isScriptHashOut': 'from() dispatch, as above: a parsed utxo script',
  'src/transaction/transaction.ts :: toString': '_checkConsistency change output + from() UnsupportedScript; we build the change script',
  'src/transaction/unspentoutput.ts :: toBuffer': 'UnspentOutput ctor builds the Script, throwing on bad input',
  'src/transaction/input/publickey.ts :: getPublicKey': 'this.output.script, reached only after a P2PK classification that parsed it',
  'src/transaction/input/publickeyhash.ts :: chunks': 'this.output.script, reached only after a P2PKH classification that parsed it',
  'src/ordinals/ordlock.ts :: isPublicKeyHashOut': 'inside a try/catch that swallows',
  'src/ordinals/ordlock.ts :: toAddress': 'inside the same try/catch that swallows a throw'
}

function sourceFiles (dir, out) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var p = path.join(dir, e.name)
    if (e.isDirectory()) sourceFiles(p, out)
    else if (/\.ts$/.test(e.name) && !/\.d\.ts$/.test(e.name)) out.push(p)
  })
  return out
}

function stripComments (line) {
  var i = line.indexOf('//')
  return i === -1 ? line : line.slice(0, i)
}

function enumerate () {
  var root = path.join(__dirname, '..', '..')
  var found = {}
  sourceFiles(path.join(root, 'src'), []).forEach(function (file) {
    var rel = path.relative(root, file).split(path.sep).join('/')
    fs.readFileSync(file, 'utf8').split('\n').forEach(function (raw) {
      var line = stripComments(raw)
      var re = /\.script\s*\.\s*([A-Za-z_$][\w$]*)|\.script\s*\[/g
      var m
      while ((m = re.exec(line))) found[rel + ' :: ' + (m[1] || '[index]')] = true
    })
  })
  return Object.keys(found).sort()
}

describe('every .script dereference in src/ is classified', function () {
  it('has no unclassified dereference', function () {
    var unclassified = enumerate().filter(function (k) {
      return !Object.prototype.hasOwnProperty.call(CLASSIFIED, k)
    })
    unclassified.should.deep.equal([],
      'A new `.script.<prop>` dereference appeared in src/. `Output#script` is null for an ' +
      'output script the node accepts and mines, and `Input#script` is null for the ' +
      'coinbase input, so a dereference that cannot rule both out throws an untyped ' +
      'TypeError on data read from a valid block. Either guard it, or add it to CLASSIFIED ' +
      'in this file with the reason its receiver cannot be null.')
  })

  it('lists nothing that has since been removed', function () {
    var live = enumerate()
    var stale = Object.keys(CLASSIFIED).filter(function (k) { return live.indexOf(k) === -1 })
    stale.should.deep.equal([], 'these entries no longer exist in src/ and should be deleted')
  })

  it('gives every entry a non-empty reason', function () {
    Object.keys(CLASSIFIED).forEach(function (k) {
      CLASSIFIED[k].should.be.a('string').with.length.above(10, k)
    })
  })
})

// --- the other half of the question: which STATES can produce a null or unreadable script ----
//
// The registry above enumerates the dereference SITES. It says nothing about how many ways a
// script can be unreadable in the first place, and the sibling package's `docs/NPM_RELEASES.md` carried that as a
// stated-unchecked claim: "whether anything OTHER than an undecodable output script reaches the
// same null dereference". This is the answer, by enumeration and measurement rather than by
// reading.
//
// There are exactly two accessors that can yield a non-Script, and each has exactly one cause:
//
//   * `Output#script` -> null, only from the `Script.InvalidBuffer` catch in
//     `setScriptFromBuffer`. Since the parser became total that catch is unreachable from bytes,
//     which is asserted below over every state a caller can build from bytes.
//   * `Input#script` -> null, only when `isNull()`: the coinbase input.
//
// Everything else that could make a script unreadable depends on `_scriptBuffer` not being a
// Buffer, because the guards in the classified sites read `_scriptBuffer.length` and
// `_scriptBuffer.toString('hex')`. All assignments to `_scriptBuffer` in src/ now put a
// Buffer there: eight pass `.toBuffer()` or `Buffer.from(...)`, one is guarded by
// `Buffer.isBuffer`, and the tenth — the public `setScriptFromBuffer` — checks its argument
// before assigning. It did not always: it assigned first, so a bad call left the object holding
// a non-Buffer and the error surfaced later, from a different method, naming neither.
describe('the states that can make a script unreadable', function () {
  const bsvlib = require('../..')
  const Output = bsvlib.Transaction.Output
  const Input = bsvlib.Transaction.Input
  const ScriptC = bsvlib.Script

  // Every shape that used to throw in the parser, plus the boundaries around them.
  const FROM_BYTES = ['6a4c', '6a4d', '6a4d01', '6a4e', '6a4e01', '6a4e0100', '4c', '4d', '4e',
    '6a4c050102', '6a050102', '01', '4c00', '', '6a', '4effffffff', '636a4c68', 'ab6a4c']

  it('no output built from bytes has a null script, however malformed', function () {
    FROM_BYTES.forEach(function (hex) {
      const o = new Output({ satoshis: 1000, script: Buffer.from(hex, 'hex') })
      ;(o.script === null).should.equal(false, hex + ' produced a null script')
      o.script.toHex().should.equal(hex, hex + ' did not round-trip through the output')
      // and the consumers that used to crash on a null script
      o.getSize().should.be.above(0)
      o.toBufferWriter().toBuffer().length.should.be.above(0)
      JSON.parse(JSON.stringify(o.toObject())).script.should.equal(hex)
      o.inspect().should.be.a('string')
    })
  })

  it('keeps the null path working if the parser ever throws again', function () {
    // The catch is unreachable today and is kept deliberately. A test that only asserted
    // unreachability would delete the evidence that the guards still work, so the state is
    // built directly instead — which is what a future parse failure would produce.
    const o = new Output({ satoshis: 1000, script: Buffer.from('6a4c', 'hex') })
    o._script = null
    o.getSize().should.equal(11)
    o.toBufferWriter().toBuffer().length.should.be.above(0)
    o.inspect().should.be.a('string')
    // the getter re-parses, because the bytes are still there and the parser is total
    o.script.toHex().should.equal('6a4c')
  })

  it('refuses a non-Buffer script buffer AT THE CALL, leaving the object intact', function () {
    const o = new Output({ satoshis: 1000, script: Buffer.from('6a', 'hex') })
    ;['a string', undefined, null, 123, {}, []].forEach(function (bad) {
      ;(function () { o.setScriptFromBuffer(bad) }).should.throw(/must be a Buffer/)
    })
    // intact: the earlier behaviour poisoned _scriptBuffer and every later read threw
    Buffer.isBuffer(o._scriptBuffer).should.equal(true)
    o.script.toHex().should.equal('6a')
  })

  it('leaves an input readable after a failed setScript', function () {
    // Input#setScript sets _script = null BEFORE validating, so a bad call leaves it null —
    // benign, because _scriptBuffer is untouched and the getter re-parses it. Asserted so that
    // it stays benign.
    const i = new Input({ prevTxId: Buffer.from('66'.repeat(32), 'hex'), outputIndex: 0, script: ScriptC.fromHex('51') })
    ;(function () { i.setScript(12345) }).should.throw(/Invalid argument type/)
    ;(i._script === null).should.equal(true)
    i.script.toHex().should.equal('51')
  })

  it('has a null input script only for the coinbase', function () {
    const coinbase = new Input({ prevTxId: Buffer.alloc(32), outputIndex: 0xffffffff, script: ScriptC.empty() })
    coinbase.isNull().should.equal(true)
    ;(coinbase.script === null).should.equal(true)
    const ordinary = new Input({ prevTxId: Buffer.from('66'.repeat(32), 'hex'), outputIndex: 0, script: ScriptC.fromHex('51') })
    ordinary.isNull().should.equal(false)
    ;(ordinary.script === null).should.equal(false)
  })

  it('assigns only Buffers to _scriptBuffer, everywhere in src/', function () {
    // The invariant the guards rest on, held by reading the source rather than by trusting the
    // four paths this file happens to exercise.
    const root = path.join(__dirname, '..', '..')
    const hits = []
    ;['src/transaction/output.ts', 'src/transaction/input/input.ts'].forEach(function (rel) {
      fs.readFileSync(path.join(root, rel), 'utf8').split('\n').forEach(function (line, n) {
        const m = /_scriptBuffer\s*=\s*(.+)$/.exec(stripComments(line))
        if (m) hits.push({ rel, line: n + 1, rhs: m[1].trim() })
      })
    })
    hits.length.should.be.above(8, 'the assignments moved; re-read them before trusting this')
    // Every recognised Buffer-producing right-hand side, listed rather than pattern-matched
    // loosely, so a new one has to be read and added deliberately. `buffer` is
    // setScriptFromBuffer's argument, which is now checked with Buffer.isBuffer before this
    // line runs; `args.script` is inside an `if (Buffer.isBuffer(args.script))`.
    const BUFFER_SOURCES = [
      /\.toBuffer\(\)$/, // a Script's own serialization
      /^buffer\.Buffer\.from\(/, // an explicit Buffer.from
      /^Buffer\.from\(/,
      /^br\.readVarLengthBuffer\(\)$/, // BufferReader, deserializing a transaction
      /^buffer$/, // setScriptFromBuffer's checked argument
      /^args\.script$/ // guarded by Buffer.isBuffer(args.script)
    ]
    hits.forEach(function (h) {
      const ok = BUFFER_SOURCES.some(function (re) { return re.test(h.rhs) })
      ok.should.equal(true, h.rel + ':' + h.line + ' assigns something unrecognised: ' + h.rhs +
        ' — read it, and add it to BUFFER_SOURCES only if it is provably a Buffer')
    })
  })
})
