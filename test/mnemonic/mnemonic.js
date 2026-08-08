'use strict'

const chai = require('chai')
const should = chai.should()

const Mnemonic = require('../../lib/mnemonic')
const errors = require('../../').errors
const bip39vectors = require('./data/fixtures.json')

describe('Mnemonic', function () {
  this.timeout(30000)

  it('should initialize the class', function () {
    should.exist(Mnemonic)
  })

  describe('@fromRandom', function () {
    it('should make a new mnemonic', function () {
      const mnemonic = Mnemonic.fromRandom()
      const mnemonic2 = Mnemonic.fromRandom()
      mnemonic.toString().should.not.equal(mnemonic2.toString())
      Mnemonic.Words.ENGLISH.includes(mnemonic.toString().split(' ')[0]).should.equal(true)
      Mnemonic.Words.ENGLISH.includes(mnemonic.toString().split(' ')[1]).should.equal(true)
      Mnemonic.Words.ENGLISH.includes(mnemonic.toString().split(' ')[2]).should.equal(true)
      const mnemonic3 = Mnemonic.fromRandom(Mnemonic.Words.SPANISH)
      Mnemonic.Words.SPANISH.includes(mnemonic3.toString().split(' ')[0]).should.equal(true)
      Mnemonic.Words.SPANISH.includes(mnemonic3.toString().split(' ')[1]).should.equal(true)
      Mnemonic.Words.SPANISH.includes(mnemonic3.toString().split(' ')[2]).should.equal(true)
    })

    // Regression: the second argument used to be silently dropped, so the
    // documented fromRandom(wordlist, 256) form returned a WEAK 12-word phrase.
    function wordCount (m) { return m.toString().split(' ').length }

    it('defaults to a 12-word (128-bit) phrase', function () {
      wordCount(Mnemonic.fromRandom()).should.equal(12)
      wordCount(Mnemonic.fromRandom(Mnemonic.Words.ENGLISH)).should.equal(12)
    })

    it('honours entropy passed as the second argument (wordlist, ent)', function () {
      // The previously-broken documented form: must now yield 24 words.
      wordCount(Mnemonic.fromRandom(Mnemonic.Words.ENGLISH, 256)).should.equal(24)
      wordCount(Mnemonic.fromRandom(Mnemonic.Words.ENGLISH, 192)).should.equal(18)
      wordCount(Mnemonic.fromRandom(Mnemonic.Words.ENGLISH, 160)).should.equal(15)
    })

    it('honours entropy passed as the first argument (ent) or (ent, wordlist)', function () {
      wordCount(Mnemonic.fromRandom(256)).should.equal(24)
      const es = Mnemonic.fromRandom(256, Mnemonic.Words.SPANISH)
      wordCount(es).should.equal(24)
      Mnemonic.Words.SPANISH.includes(es.toString().split(' ')[0]).should.equal(true)
    })

    it('throws on invalid entropy instead of silently degrading', function () {
      ;(function () { Mnemonic.fromRandom(Mnemonic.Words.ENGLISH, 200) }).should.throw(/ENT/)
      ;(function () { Mnemonic.fromRandom(64) }).should.throw(/ENT/)
    })

    it('reports a meaningful arity (2), not 0', function () {
      Mnemonic.fromRandom.length.should.equal(2)
    })
  })

  describe('# Mnemonic', function () {
    describe('Constructor', function () {
      it('does not require new keyword', function () {
        const mnemonic = Mnemonic()
        mnemonic.should.be.instanceof(Mnemonic)
      })

      it('should fail with invalid data', function () {
        (function () {
          return new Mnemonic({})
        }).should.throw(errors.InvalidArgument)
      })

      it('should fail with unknown word list', function () {
        (function () {
          return new Mnemonic('pilots foster august tomorrow kit daughter unknown awesome model town village master')
        }).should.throw(errors.Mnemonic.UnknownWordlist)
      })

      it('should fail with invalid mnemonic', function () {
        (function () {
          return new Mnemonic('monster foster august tomorrow kit daughter unknown awesome model town village pilot')
        }).should.throw(errors.Mnemonic.InvalidMnemonic)
      })

      it('should fail with invalid ENT', function () {
        (function () {
          return new Mnemonic(64)
        }).should.throw(errors.InvalidArgument)
      })

      it('constructor defaults to english worldlist', function () {
        const mnemonic = new Mnemonic()
        mnemonic.wordlist.should.equal(Mnemonic.Words.ENGLISH)
      })

      it('allow using different worldlists', function () {
        const mnemonic = new Mnemonic(Mnemonic.Words.SPANISH)
        mnemonic.wordlist.should.equal(Mnemonic.Words.SPANISH)
      })

      it('constructor honor both length and wordlist', function () {
        const mnemonic = new Mnemonic(32 * 7, Mnemonic.Words.SPANISH)
        mnemonic.phrase.split(' ').length.should.equal(21)
        mnemonic.wordlist.should.equal(Mnemonic.Words.SPANISH)
      })

      it('constructor should detect standard wordlist', function () {
        const mnemonic = new Mnemonic('afirmar diseño hielo fideo etapa ogro cambio fideo toalla pomelo número buscar')
        mnemonic.wordlist.should.equal(Mnemonic.Words.SPANISH)
      })
    })

    it('english wordlist is complete', function () {
      Mnemonic.Words.ENGLISH.length.should.equal(2048)
      Mnemonic.Words.ENGLISH[0].should.equal('abandon')
    })

    it('spanish wordlist is complete', function () {
      Mnemonic.Words.SPANISH.length.should.equal(2048)
      Mnemonic.Words.SPANISH[0].should.equal('ábaco')
    })

    it('japanese wordlist is complete', function () {
      Mnemonic.Words.JAPANESE.length.should.equal(2048)
      Mnemonic.Words.JAPANESE[0].should.equal('あいこくしん')
    })

    it('chinese wordlist is complete', function () {
      Mnemonic.Words.CHINESE.length.should.equal(2048)
      Mnemonic.Words.CHINESE[0].should.equal('的')
    })

    it('french wordlist is complete', function () {
      Mnemonic.Words.FRENCH.length.should.equal(2048)
      Mnemonic.Words.FRENCH[0].should.equal('abaisser')
    })

    it('italian wordlist is complete', function () {
      Mnemonic.Words.ITALIAN.length.should.equal(2048)
      Mnemonic.Words.ITALIAN[0].should.equal('abaco')
    })

    it('allows use different phrase lengths', function () {
      let mnemonic

      mnemonic = new Mnemonic(32 * 4)
      mnemonic.phrase.split(' ').length.should.equal(12)

      mnemonic = new Mnemonic(32 * 5)
      mnemonic.phrase.split(' ').length.should.equal(15)

      mnemonic = new Mnemonic(32 * 6)
      mnemonic.phrase.split(' ').length.should.equal(18)

      mnemonic = new Mnemonic(32 * 7)
      mnemonic.phrase.split(' ').length.should.equal(21)

      mnemonic = new Mnemonic(32 * 8)
      mnemonic.phrase.split(' ').length.should.equal(24)
    })

    it('validates a phrase', function () {
      const valid = Mnemonic.isValid('afirmar diseño hielo fideo etapa ogro cambio fideo toalla pomelo número buscar')
      valid.should.equal(true)

      const invalid = Mnemonic.isValid('afirmar diseño hielo fideo etapa ogro cambio fideo hielo pomelo número buscar')
      invalid.should.equal(false)

      const invalid2 = Mnemonic.isValid('afirmar diseño hielo fideo etapa ogro cambio fideo hielo pomelo número oneInvalidWord')
      invalid2.should.equal(false)

      const invalid3 = Mnemonic.isValid('totally invalid phrase')
      invalid3.should.equal(false)

      const valid2 = Mnemonic.isValid('caution opprimer époque belote devenir ficeler filleul caneton apologie nectar frapper fouiller')
      valid2.should.equal(true)
    })

    it('has a toString method', function () {
      const mnemonic = new Mnemonic()
      mnemonic.toString().should.equal(mnemonic.phrase)
    })

    it('has a fromString method', function () {
      const mnemonic = Mnemonic.fromRandom()
      mnemonic.toString().should.equal(mnemonic.phrase)
      const mnemonic2 = Mnemonic.fromString(mnemonic.toString())
      mnemonic2.toString().should.equal(mnemonic.toString())
      const mnemonic3 = Mnemonic.fromRandom(Mnemonic.Words.SPANISH)
      const mnemonic4 = Mnemonic.fromString(mnemonic3.toString(), Mnemonic.Words.SPANISH)
      mnemonic3.toString().should.equal(mnemonic4.toString())
    })

    it('has a toString method', function () {
      const mnemonic = new Mnemonic()
      mnemonic.inspect().should.have.string('<Mnemonic:')
    })

    it('derives a seed without a passphrase', function () {
      const mnemonic = new Mnemonic()
      const seed = mnemonic.toSeed()
      seed.length.should.equal(512 / 8)
      should.exist(seed)
    })

    it('derives a seed using a passphrase', function () {
      const mnemonic = new Mnemonic()
      const seed = mnemonic.toSeed('my passphrase')
      should.exist(seed)
    })

    it('derives an extended private key', function () {
      const mnemonic = new Mnemonic()
      const pk = mnemonic.toHDPrivateKey()
      should.exist(pk)
    })

    it('Mnemonic.fromSeed should fail with invalid wordlist', function () {
      (function () {
        return Mnemonic.fromSeed(Buffer.alloc(1))
      }).should.throw(errors.InvalidArgument)
    })

    it('Mnemonic.fromSeed should fail with invalid seed', function () {
      (function () {
        return Mnemonic.fromSeed()
      }).should.throw(errors.InvalidArgument)
    })

    it('Constructor should fail with invalid seed', function () {
      (function () {
        return new Mnemonic(Buffer.alloc(1))
      }).should.throw(errors.InvalidEntropy)
    })

    // To add new vectors for different languages:
    // 1. Add and implement the wordlist so it appears in Mnemonic.Words
    // 2. Add the vectors and make sure the key is lowercase of the key for Mnemonic.Words
    const vectorwordlists = {}

    for (const key in Mnemonic.Words) {
      if (Mnemonic.Words.hasOwnProperty(key)) {
        vectorwordlists[key.toLowerCase()] = Mnemonic.Words[key]
      }
    }

    const testvector = function (v, lang) {
      it('should pass test vector for ' + lang + ' #' + v, function () {
        const wordlist = vectorwordlists[lang]
        const vector = bip39vectors[lang][v]
        const code = vector[1]
        const mnemonic = vector[2]
        const seed = vector[3]
        const mnemonic1 = Mnemonic.fromSeed(Buffer.from(code, 'hex'), wordlist).phrase
        mnemonic1.should.equal(mnemonic)

        const m = new Mnemonic(mnemonic)
        const seed1 = m.toSeed(vector[0])
        seed1.toString('hex').should.equal(seed)

        Mnemonic.isValid(mnemonic, wordlist).should.equal(true)
      })
    }

    for (const key in bip39vectors) {
      if (bip39vectors.hasOwnProperty(key)) {
        for (let v = 0; v < bip39vectors[key].length; v++) {
          testvector(v, key)
        }
      }
    }
  })
})
