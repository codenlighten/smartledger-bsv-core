'use strict'

/* global describe, it */

// Every error name this library can produce must correspond to a name in the node's
// script_error.h. Most of ours ARE the node's, spelled identically; eight are not, and
// Interpreter.NODE_ERROR_NAMES maps those.
//
// The test that matters is the third one: it SCANS THE INTERPRETER SOURCE for every
// `'SCRIPT_ERR_*'` literal it can assign to errstr, and fails if any of them neither appears in
// script_error.h nor has a mapping. So adding a novel error name without deciding what the node
// calls it breaks the build, which is the only way a published mapping stays true.
//
// Why this exists: a conformance replay of 24,568 node-validated rows reported 456 "mismatches"
// that were entirely the EVAL_FALSE granularity — four distinct authoring mistakes this library
// distinguishes and the node does not. Nothing was wrong on either side; the comparison simply
// had no mapping to apply. See the 1.4.0 changelog.

require('chai').should()
const fs = require('fs')
const path = require('path')
const bsv = require('../..')
const Interpreter = bsv.Script.Interpreter

// bitcoin-sv v1.2.3, src/script/script_error.h, verbatim and sorted. A frozen copy rather than
// a fetch: a test that reaches the network is a test that fails for reasons unrelated to the
// code. SCRIPT_ERR_OK, _LAST and _ERROR_COUNT are enum bookkeeping, not failure names, and are
// kept so this list is exactly the header's.
const NODE_ERRORS = [
  'SCRIPT_ERR_BAD_OPCODE', 'SCRIPT_ERR_BIG_INT', 'SCRIPT_ERR_CHECKMULTISIGVERIFY',
  'SCRIPT_ERR_CHECKSIGVERIFY', 'SCRIPT_ERR_CLEANSTACK', 'SCRIPT_ERR_DISABLED_OPCODE',
  'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS', 'SCRIPT_ERR_DIV_BY_ZERO', 'SCRIPT_ERR_EQUALVERIFY',
  'SCRIPT_ERR_ERROR_COUNT', 'SCRIPT_ERR_EVAL_FALSE', 'SCRIPT_ERR_ILLEGAL_CHRONICLE',
  'SCRIPT_ERR_ILLEGAL_FORKID', 'SCRIPT_ERR_IMPOSSIBLE_ENCODING',
  'SCRIPT_ERR_INVALID_ALTSTACK_OPERATION', 'SCRIPT_ERR_INVALID_FLAGS',
  'SCRIPT_ERR_INVALID_NUMBER_RANGE', 'SCRIPT_ERR_INVALID_OPERAND_SIZE',
  'SCRIPT_ERR_INVALID_SPLIT_RANGE', 'SCRIPT_ERR_INVALID_STACK_OPERATION', 'SCRIPT_ERR_LAST',
  'SCRIPT_ERR_MINIMALDATA', 'SCRIPT_ERR_MINIMALIF', 'SCRIPT_ERR_MOD_BY_ZERO',
  'SCRIPT_ERR_MUST_USE_FORKID', 'SCRIPT_ERR_NEGATIVE_LOCKTIME',
  'SCRIPT_ERR_NONCOMPRESSED_PUBKEY', 'SCRIPT_ERR_NUMEQUALVERIFY', 'SCRIPT_ERR_OK',
  'SCRIPT_ERR_OP_COUNT', 'SCRIPT_ERR_OP_RETURN', 'SCRIPT_ERR_PUBKEY_COUNT',
  'SCRIPT_ERR_PUBKEYTYPE', 'SCRIPT_ERR_PUSH_SIZE', 'SCRIPT_ERR_SCRIPTNUM_MINENCODE',
  'SCRIPT_ERR_SCRIPTNUM_OVERFLOW', 'SCRIPT_ERR_SCRIPT_SIZE', 'SCRIPT_ERR_SIG_COUNT',
  'SCRIPT_ERR_SIG_DER', 'SCRIPT_ERR_SIG_HASHTYPE', 'SCRIPT_ERR_SIG_HIGH_S',
  'SCRIPT_ERR_SIG_NULLDUMMY', 'SCRIPT_ERR_SIG_NULLFAIL', 'SCRIPT_ERR_SIG_PUSHONLY',
  'SCRIPT_ERR_STACK_SIZE', 'SCRIPT_ERR_UNBALANCED_CONDITIONAL', 'SCRIPT_ERR_UNKNOWN_ERROR',
  'SCRIPT_ERR_UNSATISFIED_LOCKTIME', 'SCRIPT_ERR_VERIFY'
]

describe('error names, and the node\'s spelling of them', function () {
  it('leaves a name the node shares untouched', function () {
    Interpreter.toNodeErrorName('SCRIPT_ERR_BAD_OPCODE').should.equal('SCRIPT_ERR_BAD_OPCODE')
    Interpreter.toNodeErrorName('SCRIPT_ERR_MINIMALDATA').should.equal('SCRIPT_ERR_MINIMALDATA')
    // Not an error name at all: returned as given rather than guessed at.
    Interpreter.toNodeErrorName('').should.equal('')
    Interpreter.toNodeErrorName('nonsense').should.equal('nonsense')
  })

  it('collapses the four EVAL_FALSE variants the node does not distinguish', function () {
    ;['SCRIPT_ERR_EVAL_FALSE_IN_STACK', 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT',
      'SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK', 'SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK'
    ].forEach(function (ours) {
      Interpreter.toNodeErrorName(ours).should.equal('SCRIPT_ERR_EVAL_FALSE')
    })
  })

  it('corrects the four that are only spelled differently', function () {
    Interpreter.toNodeErrorName('SCRIPT_ERR_NULLFAIL').should.equal('SCRIPT_ERR_SIG_NULLFAIL')
    Interpreter.toNodeErrorName('SCRIPT_ERR_SIG_DER_HIGH_S').should.equal('SCRIPT_ERR_SIG_HIGH_S')
    Interpreter.toNodeErrorName('SCRIPT_ERR_SIG_DER_INVALID_FORMAT').should.equal('SCRIPT_ERR_SIG_DER')
    Interpreter.toNodeErrorName('SCRIPT_ERR_UNDEFINED_OPCODE').should.equal('SCRIPT_ERR_BAD_OPCODE')
  })

  it('every error name the interpreter can emit has a node equivalent', function () {
    // The guard. Scanning the source rather than enumerating by hand is the point: a hand
    // list would go stale the moment someone adds a code, which is exactly when this matters.
    // Scans the TypeScript source, so it sees a new code the moment it is written.
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'script', 'interpreter.ts'), 'utf8')
    const emitted = (src.match(/'SCRIPT_ERR_[A-Z0-9_]+'/g) || [])
      .map(function (q) { return q.slice(1, -1) })
    const unique = Object.keys(emitted.reduce(function (acc, n) { acc[n] = true; return acc }, {}))
    unique.length.should.be.above(40) // the scan found something; a zero-length pass is no pass

    const unmapped = unique.filter(function (ours) {
      return NODE_ERRORS.indexOf(Interpreter.toNodeErrorName(ours)) === -1
    })
    unmapped.should.deep.equal([],
      'these names are neither in script_error.h nor in Interpreter.NODE_ERROR_NAMES: ' +
      unmapped.join(', ') + ' — add a mapping, or use the node\'s spelling')
  })

  it('has no dead entries: everything it maps is a name we actually emit', function () {
    const src = fs.readFileSync(
      path.join(__dirname, '..', '..', 'src', 'script', 'interpreter.ts'), 'utf8')
    const dead = Object.keys(Interpreter.NODE_ERROR_NAMES).filter(function (ours) {
      return src.indexOf("'" + ours + "'") === -1
    })
    dead.should.deep.equal([], 'mapped but never emitted: ' + dead.join(', '))
  })

  it('maps to names the node really has, not to plausible-looking ones', function () {
    Object.keys(Interpreter.NODE_ERROR_NAMES).forEach(function (ours) {
      NODE_ERRORS.indexOf(Interpreter.NODE_ERROR_NAMES[ours]).should.not.equal(-1,
        ours + ' maps to ' + Interpreter.NODE_ERROR_NAMES[ours] + ', which script_error.h lacks')
    })
  })

  it('exposes it on the instance as a derived read, leaving errstr alone', function () {
    const interp = new Interpreter()
    interp.verify(new bsv.Script(), bsv.Script.fromBuffer(Buffer.from('5100', 'hex')),
      new bsv.Transaction(), 0, Interpreter.mainnetFlags(), new bsv.crypto.BN(1000))
    interp.errstr.should.equal('SCRIPT_ERR_EVAL_FALSE_IN_STACK')
    interp.nodeErrstr.should.equal('SCRIPT_ERR_EVAL_FALSE')
    // Reading it changes nothing — it is a getter, not a mode.
    interp.errstr.should.equal('SCRIPT_ERR_EVAL_FALSE_IN_STACK')
  })

  it('drops trailing detail only when the name maps', function () {
    // UNKNOWN_ERROR carries the underlying exception text and is a node name already, so the
    // detail survives. A mapped name cannot keep it: 'SCRIPT_ERR_EVAL_FALSE: ...' equals
    // nothing the node would emit.
    Interpreter.toNodeErrorName('SCRIPT_ERR_UNKNOWN_ERROR: Error: boom')
      .should.equal('SCRIPT_ERR_UNKNOWN_ERROR: Error: boom')
    Interpreter.toNodeErrorName('SCRIPT_ERR_EVAL_FALSE_NO_RESULT: trailing')
      .should.equal('SCRIPT_ERR_EVAL_FALSE')
  })
})
