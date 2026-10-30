'use strict'

/* global describe, it */

// A mechanical gate behind test/security/inherited_options.js. That file proves specific options
// resist pollution; this one stops the next read of a protected option from going back to plain
// property access. It was written because the first pass converted only the option names its
// author knew of, and an independent check found five it missed (allowEmptyLock,
// allowUnknownEvenFields, minConfirmations, minDifficulty and a statuslist call that copied a
// plain read into a fresh object, which turned an inherited value into an OWN one).
//
// The protected set is not a list kept here: it is every key src/ already reads through
// ownOption(), so converting one option protects its other readers too. A new option still has
// to be converted by hand — this cannot know that a name is security-relevant.

require('chai').should()
const fs = require('fs')
const path = require('path')

const LIB = path.join(__dirname, '..', '..', 'src')

function jsFiles (dir) {
  let out = []
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    const full = path.join(dir, e.name)
    if (e.isDirectory()) out = out.concat(jsFiles(full))
    else if (e.name.slice(-3) === '.ts' && e.name.slice(-5) !== '.d.ts') out.push(full)
  })
  return out
}

// What an options object is called in this codebase. A key read off anything else (an
// instance property such as this.allowNonEnforcing, which was copied from the options once)
// is not an options read.
const OPTION_OBJECTS = '(?:o|opts|opt|options|params|config|unsafe|this\\.options|this\\.opts)'

// A key that is protected in one place and an ordinary DATA field in another. `max` limits the
// consensus statics in Interpreter.useMainnetConsensus, and is also the required max-supply field
// of a BSV-20 deploy, which is a value the caller must supply and not an option that changes a
// check. Listed by file so a new plain read of `max` anywhere else is still reported.
const DATA_FIELD_EXCEPTIONS = { 'ordinals/bsv20.ts': ['max'] }

function code (line) {
  const t = line.trim()
  return !(t.indexOf('*') === 0 || t.indexOf('//') === 0 || t.indexOf('/*') === 0)
}

describe('security: protected options are only read through ownOption', function () {
  const files = jsFiles(LIB).filter(function (f) { return f.slice(-17) !== 'util/own-option.ts' })
  const keys = {}
  files.forEach(function (f) {
    const re = /ownOption(?:<[^>]*>)?\([^,()]+(?:\.[A-Za-z]+)?, '([A-Za-z]+)'\)/g
    let m
    const src = fs.readFileSync(f, 'utf8')
    while ((m = re.exec(src))) keys[m[1]] = true
  })

  it('finds a real set of protected options (the scan is not vacuous)', function () {
    Object.keys(keys).length.should.be.above(12)
    ;['requirePow', 'allowEmptyLock', 'minWork', 'afterChronicle', 'disableAll']
      .forEach(function (k) { keys.should.have.property(k, true) })
  })

  it('has no plain read of any protected option off an options object', function () {
    const bad = []
    files.forEach(function (f) {
      fs.readFileSync(f, 'utf8').split('\n').forEach(function (line, i) {
        if (!code(line)) return
        // A quoted mention is an error message or documentation, not a read.
        const stripped = line.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""')
        Object.keys(keys).forEach(function (k) {
          const excused = DATA_FIELD_EXCEPTIONS[path.relative(LIB, f)]
          if (excused && excused.indexOf(k) !== -1) return
          if (new RegExp('(?<![\\w.])' + OPTION_OBJECTS + '\\.' + k + '\\b').test(stripped)) {
            bad.push(path.relative(LIB, f) + ':' + (i + 1) + ' reads .' + k + ' directly')
          }
        })
      })
    })
    bad.should.deep.equal([])
  })

  it('the scan sees a plain read when one is planted (positive control)', function () {
    const planted = 'var x = opts.requirePow !== false'
    const stripped = planted.replace(/'(?:[^'\\]|\\.)*'/g, "''")
    new RegExp('(?<![\\w.])' + OPTION_OBJECTS + '\\.requirePow\\b').test(stripped).should.equal(true)
    new RegExp('(?<![\\w.])' + OPTION_OBJECTS + '\\.requirePow\\b')
      .test("var x = ownOption(opts, 'requirePow') !== false".replace(/'(?:[^'\\]|\\.)*'/g, "''")).should.equal(false)
  })
})
