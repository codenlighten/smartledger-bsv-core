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
