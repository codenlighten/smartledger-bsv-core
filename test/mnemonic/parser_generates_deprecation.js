'use strict'

require('chai').should()
var bsv = require('../..')
var deprecate = require('../../dist/util/deprecate')

/**
 * A NAMED PARSER handed nothing generated a key the caller never supplied; a sibling deployment
 * lost 10,000 sat to it. The notice is on the parsers and NOT on the constructors, because
 * `new Mnemonic()` generating on no argument is documented and intended — a test asserting "no
 * key appears from nowhere" would fail on correct behaviour, so the halves are kept apart.
 *
 * Ported with the sibling's plan ids (see docs/RELEASE-2.0.0.md), with `removeIn` 2.0.0 here.
 */
describe('key-material parsers handed nothing — warn in 1.10.0, refuse in 2.0.0', function () {
  var NOTHING = [undefined, null, '', 0, false, [], bsv.Mnemonic.Words.ENGLISH, Buffer.alloc(16)]
  var warned

  beforeEach(function () {
    deprecate.reset()
    warned = []
    this.origWarn = console.warn
    console.warn = function (m) { warned.push(m) }
  })
  afterEach(function () {
    console.warn = this.origWarn
    deprecate.reset()
  })

  it('warns for every input that generates, and still generates, so nothing breaks', function () {
    NOTHING.forEach(function (v) {
      deprecate.reset()
      warned = []
      var m = bsv.Mnemonic.fromString(v)
      m.toString().split(' ').length.should.equal(12)
      warned.length.should.equal(1, 'no notice for ' + Object.prototype.toString.call(v))
      warned[0].should.match(/removed in 2\.0\.0/)
      deprecate.fired()[0].plan.should.equal('mnemonic-fromstring-generates')
    })
  })

  it('is silent for a valid phrase and still round-trips it, with and without a wordlist', function () {
    var phrase = bsv.Mnemonic.fromRandom().toString()
    bsv.Mnemonic.fromString(phrase).toString().should.equal(phrase)
    bsv.Mnemonic.fromString(phrase, bsv.Mnemonic.Words.ENGLISH).toString().should.equal(phrase)
    warned.length.should.equal(0)
  })

  it('does not warn for whitespace, which already throws — but does for a trimming call site', function () {
    ;(function () { bsv.Mnemonic.fromString('   ') }).should.throw()
    warned.length.should.equal(0)
    bsv.Mnemonic.fromString('   '.trim()).toString().split(' ').length.should.equal(12)
    warned.length.should.equal(1)
  })

  it('the two derivable-by-anyone cases are still exactly that, so the notice is not cosmetic', function () {
    var a = bsv.Mnemonic.fromString([]).toString()
    bsv.Mnemonic.fromString([]).toString().should.equal(a)
    a.trim().should.equal('')
    bsv.Mnemonic.fromString(Buffer.alloc(16)).toString()
      .should.equal('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
  })

  it('HDPrivateKey.fromString: warns on empty, still throws on undefined, silent on a real xprv', function () {
    bsv.HDPrivateKey.fromString('').should.be.an.instanceOf(bsv.HDPrivateKey)
    warned.length.should.equal(1)
    deprecate.fired()[0].plan.should.equal('hdprivatekey-fromstring-empty')

    deprecate.reset(); warned = []
    ;(function () { bsv.HDPrivateKey.fromString(undefined) }).should.throw(/No valid string/)
    warned.length.should.equal(0, 'undefined was already refused; it must not also warn')

    var xprv = new bsv.HDPrivateKey().toString()
    bsv.HDPrivateKey.fromString(xprv).toString().should.equal(xprv)
    warned.length.should.equal(0)
  })

  it('the PrivateKey siblings already apply the rule, so they neither warn nor accept', function () {
    ;['fromString', 'fromWIF'].forEach(function (fn) {
      NOTHING.forEach(function (v) {
        ;(function () { bsv.PrivateKey[fn](v) }).should.throw()
      })
    })
    warned.length.should.equal(0)
  })
})
