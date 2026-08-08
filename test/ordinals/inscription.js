'use strict'

/* global describe, it */

// 1Sat Ordinals inscription build/parse round-trip + output construction.

require('chai').should()
const bsv = require('../..')
const Ord = bsv.Ordinals

describe('Ordinals inscriptions', function () {
  const key = bsv.PrivateKey.fromRandom()
  const address = key.toAddress()

  it('builds a P2PKH inscription and round-trips through parse', function () {
    const s = Ord.buildInscription({
      address, contentType: 'text/plain', content: 'hello ordinals'
    })
    const parsed = Ord.parseInscription(s)
    parsed.should.be.an('object')
    parsed.contentType.should.equal('text/plain')
    parsed.contentText.should.equal('hello ordinals')
    // The base lock is exactly the P2PKH for the address.
    parsed.lock.toHex().should.equal(bsv.Script.buildPublicKeyHashOut(address).toHex())
  })

  it('preserves binary content and content-type exactly', function () {
    const content = bsv.crypto.Random.getRandomBuffer(64)
    const s = Ord.buildInscription({ address, contentType: 'image/png', content })
    const parsed = Ord.parseInscription(s)
    parsed.contentType.should.equal('image/png')
    parsed.content.equals(content).should.equal(true)
  })

  it('round-trips through hex serialization', function () {
    const s = Ord.buildInscription({ address, contentType: 'application/json', content: '{"a":1}' })
    const parsed = Ord.parseInscription(s.toHex())
    parsed.contentText.should.equal('{"a":1}')
    parsed.contentType.should.equal('application/json')
  })

  it('accepts a custom base lock script', function () {
    const lock = bsv.Script.buildPublicKeyHashOut(address)
    const s = Ord.buildInscription({ lock, contentType: 'text/plain', content: 'x' })
    Ord.isInscription(s).should.equal(true)
    Ord.parseInscription(s).lock.toHex().should.equal(lock.toHex())
  })

  it('isInscription is false for a plain P2PKH script', function () {
    const p2pkh = bsv.Script.buildPublicKeyHashOut(address)
    Ord.isInscription(p2pkh).should.equal(false)
    const isNull = Ord.parseInscription(p2pkh) === null
    isNull.should.equal(true)
  })

  it('createInscriptionOutput is a 1-sat output carrying the inscription', function () {
    const out = Ord.createInscriptionOutput({ address, contentType: 'text/plain', content: 'hi' })
    out.satoshis.should.equal(1)
    Ord.isInscription(out.script).should.equal(true)
  })

  it('batchInscriptionOutputs builds one output per item', function () {
    const outs = Ord.batchInscriptionOutputs([
      { address, contentType: 'text/plain', content: 'a' },
      { address, contentType: 'text/plain', content: 'b' }
    ])
    outs.length.should.equal(2)
    Ord.parseInscription(outs[0].script).contentText.should.equal('a')
    Ord.parseInscription(outs[1].script).contentText.should.equal('b')
  })

  // The 1Sat spec allows the locking script to be prepended OR appended to the
  // envelope. The parser only ever looked before it, so an appended lock was dropped
  // and an owned ordinal was reported as carrying no locking script at all.
  describe('recovers the lock wherever the spec allows it to sit', function () {
    const p2pkh = bsv.Script.buildPublicKeyHashOut(address)

    function concat () {
      const out = new bsv.Script()
      Array.prototype.slice.call(arguments).forEach(function (part) {
        part.chunks.forEach(function (c) { out.chunks.push(c) })
      })
      return out
    }

    function envelope () {
      return Ord.buildInscription({
        lock: new bsv.Script(), allowEmptyLock: true, contentType: 'text/plain', content: 'hello'
      })
    }

    it('recovers a lock that precedes the envelope', function () {
      const parsed = Ord.parseInscription(concat(p2pkh, envelope()))
      parsed.lock.toHex().should.equal(p2pkh.toHex())
      parsed.contentText.should.equal('hello')
    })

    it('recovers a lock that follows the envelope', function () {
      const parsed = Ord.parseInscription(concat(envelope(), p2pkh))
      parsed.lock.toHex().should.equal(p2pkh.toHex())
      parsed.contentText.should.equal('hello')
    })

    it('keeps a separating OP_CODESEPARATOR, which really does run', function () {
      const sep = concat(p2pkh, new bsv.Script().add(bsv.Opcode.OP_CODESEPARATOR), envelope())
      const parsed = Ord.parseInscription(sep)
      parsed.lock.chunks.length.should.equal(p2pkh.chunks.length + 1)
      parsed.contentText.should.equal('hello')
    })

    it('still reports no lock when there genuinely is none', function () {
      Ord.parseInscription(envelope()).lock.chunks.length.should.equal(0)
    })
  })

  // Every case below used to succeed and emit a well-formed script that inscribed
  // something other than what the caller asked for. An inscription is permanent, so
  // each one now fails loudly at build time instead of on-chain.
  describe('rejects arguments that would silently inscribe the wrong thing', function () {
    it('throws when content is omitted rather than inscribing an empty payload', function () {
      (function () {
        Ord.buildInscription({ address, contentType: 'text/plain' })
      }).should.throw(/requires `content`/)
    })

    it('names the field the caller actually passed', function () {
      // The real-world report: a wallet whose own builder calls the field `data`.
      (function () {
        Ord.buildInscription({ address, contentType: 'text/plain', data: 'hello world' })
      }).should.throw(/received `data`, which is not read/)
    })

    it('still allows an explicitly empty payload', function () {
      const s = Ord.buildInscription({ address, contentType: 'text/plain', content: '' })
      Ord.parseInscription(s).content.length.should.equal(0)
    })

    it('throws rather than stringifying an object into the payload', function () {
      // String({}) is '[object Object]' — permanent, and never intended.
      (function () {
        Ord.buildInscription({ address, contentType: 'text/plain', content: { a: 1 } })
      }).should.throw(/content must be a string or Buffer, got an object/)
    })

    it('throws on any non-string, non-Buffer content', function () {
      [42, true, null, ['a'], undefined].forEach(function (v) {
        (function () {
          Ord.buildInscription({ address, contentType: 'text/plain', content: v })
        }).should.throw(Error)
      })
    })

    it('requires a contentType for Buffer content instead of labelling it text/plain', function () {
      const png = Buffer.from([0x89, 0x50, 0x4e, 0x47])
      ;(function () {
        Ord.buildInscription({ address, content: png })
      }).should.throw(/contentType is required when content is a Buffer/)
      // Declared explicitly, it builds.
      const s = Ord.buildInscription({ address, contentType: 'image/png', content: png })
      Ord.parseInscription(s).contentType.should.equal('image/png')
    })

    it('keeps the text/plain default for string content', function () {
      const s = Ord.buildInscription({ address, content: 'hi' })
      Ord.parseInscription(s).contentType.should.equal('text/plain')
    })

    it('throws on an empty or non-string contentType', function () {
      (function () {
        Ord.buildInscription({ address, contentType: '', content: 'x' })
      }).should.throw(/contentType must not be empty/)
      ;(function () {
        Ord.buildInscription({ address, contentType: {}, content: 'x' })
      }).should.throw(/contentType must be a string or Buffer/)
    })

    it('throws on an empty base lock, which would be anyone-can-spend', function () {
      // With no base lock the script is just the inert envelope: OP_FALSE OP_IF skips
      // to OP_ENDIF, so whatever the spender pushed is the final stack and any spender
      // succeeds. Proven below rather than asserted.
      (function () {
        Ord.buildInscription({ lock: Buffer.alloc(0), contentType: 'text/plain', content: 'x' })
      }).should.throw(/spendable by anyone/)
    })

    it('proves the empty-lock script really is anyone-can-spend', function () {
      const envelope = Ord.buildInscription({
        lock: new bsv.Script(), allowEmptyLock: true, contentType: 'text/plain', content: 'x'
      })
      // An unlocking script from a key unrelated to `address` satisfies it.
      const unlock = new bsv.Script().add(bsv.Opcode.OP_1)
      const interp = new bsv.Script.Interpreter()
      const ok = interp.verify(unlock, envelope, new bsv.Transaction(), 0, 0)
      ok.should.equal(true)
    })

    it('permits an empty lock only when the caller opts in', function () {
      const s = Ord.buildInscription({
        lock: new bsv.Script(), allowEmptyLock: true, contentType: 'text/plain', content: 'x'
      })
      Ord.isInscription(s).should.equal(true)
    })

    it('throws when both lock and address are given instead of ignoring one', function () {
      const lock = bsv.Script.buildPublicKeyHashOut(address)
      const other = bsv.PrivateKey.fromRandom().toAddress()
      ;(function () {
        Ord.buildInscription({ lock, address: other, contentType: 'text/plain', content: 'x' })
      }).should.throw(/not both/)
    })

    it('rejects a satoshi amount that carries no ordinal', function () {
      [0, '1', 1.5, -1].forEach(function (v) {
        (function () {
          Ord.createInscriptionOutput({
            address, contentType: 'text/plain', content: 'x', satoshis: v
          })
        }).should.throw(Error)
      })
      Ord.createInscriptionOutput({
        address, contentType: 'text/plain', content: 'x'
      }).satoshis.should.equal(1)
    })
  })

  // The case that motivated making the script-size cap configurable: transferring a
  // large inscription. The envelope is inert, so the spend is an ordinary P2PKH — but
  // the interpreter could not even load the script, because total script size was a
  // hard-coded 10,000 bytes that useGenesisLimits() did not lift.
  describe('transferring a large inscription', function () {
    const I = bsv.Script.Interpreter
    const Sighash = bsv.Transaction.Sighash
    const BN = bsv.crypto.BN
    const SIGHASH = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID
    const FLAGS = I.SCRIPT_VERIFY_STRICTENC | I.SCRIPT_ENABLE_SIGHASH_FORKID
    let saved

    beforeEach(function () { saved = I.getLimits() })
    afterEach(function () { I.setLimits(saved) })

    // A signed transfer of a `kb`-sized inscription to a new owner.
    function transfer (kb) {
      const owner = bsv.PrivateKey.fromBuffer(Buffer.alloc(32, 11))
      const recipient = bsv.PrivateKey.fromBuffer(Buffer.alloc(32, 22))
      const lock = Ord.buildInscription({
        address: owner.toAddress(),
        contentType: 'image/png',
        content: bsv.crypto.Random.getRandomBuffer(kb * 1024)
      })
      const spend = new bsv.Transaction()
      spend.addInput(new bsv.Transaction.Input({
        prevTxId: 'aa'.repeat(32), outputIndex: 0, script: bsv.Script.empty()
      }), lock, 1)
      spend.addOutput(new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(recipient.toAddress()), satoshis: 1
      }))
      // Sign over the FULL previous locking script — envelope included. That is the
      // script code the network uses; signing the base lock alone yields a signature
      // that verifies against its own preimage and nothing else.
      const sig = Sighash.sign(spend, owner, SIGHASH, 0, lock, new BN(1), FLAGS)
      const unlock = new bsv.Script()
        .add(Buffer.concat([sig.toDER(), Buffer.from([SIGHASH])]))
        .add(owner.toPublicKey().toBuffer())
      spend.inputs[0].setScript(unlock)
      return { lock, unlock, spend, sig, owner }
    }

    function evaluate (t) {
      const interp = new I()
      const ok = interp.verify(t.unlock, t.lock, t.spend, 0, FLAGS, new BN(1))
      return { ok, err: interp.errstr }
    }

    it('cannot be evaluated under pre-Genesis limits — two separate caps bite', function () {
      // Under 10 KB the script loads and the 520-byte push cap rejects the content...
      const small = evaluate(transfer(3))
      small.ok.should.equal(false)
      small.err.should.equal('SCRIPT_ERR_PUSH_SIZE')
      // ...over 10 KB it never gets that far: evaluate() refuses the script outright.
      // This is the cap useGenesisLimits() could not lift.
      const big = evaluate(transfer(50))
      big.ok.should.equal(false)
      big.err.should.equal('SCRIPT_ERR_SCRIPT_SIZE')
    })

    it('evaluates once Genesis limits are enabled', function () {
      bsv.Covenant.Helpers.enableGenesis()
      const t = transfer(50)
      t.lock.toBuffer().length.should.be.above(10000) // past the old hard-coded cap
      evaluate(t).ok.should.equal(true)
    })

    it('agrees with a direct signature check against the sighash', function () {
      // The fallback used when the interpreter cannot run: verify the signature over
      // the sighash directly. It must agree with the interpreter where both work.
      bsv.Covenant.Helpers.enableGenesis()
      const t = transfer(50)
      const hash = Sighash.sighash(t.spend, SIGHASH, 0, t.lock, new BN(1), FLAGS)
      const sigOk = bsv.crypto.ECDSA.verify(hash, t.sig, t.owner.toPublicKey(), 'little')
      sigOk.should.equal(true)
      evaluate(t).ok.should.equal(true)
    })

    it('rejects a signature made over the base lock instead of the full script', function () {
      bsv.Covenant.Helpers.enableGenesis()
      const t = transfer(50)
      const baseLock = bsv.Script.buildPublicKeyHashOut(t.owner.toAddress())
      const wrong = Sighash.sign(t.spend, t.owner, SIGHASH, 0, baseLock, new BN(1), FLAGS)
      const hash = Sighash.sighash(t.spend, SIGHASH, 0, t.lock, new BN(1), FLAGS)
      // Verifies against its own (wrong) preimage, but not the one the network checks.
      bsv.crypto.ECDSA.verify(hash, wrong, t.owner.toPublicKey(), 'little').should.equal(false)
      t.spend.inputs[0].setScript(new bsv.Script()
        .add(Buffer.concat([wrong.toDER(), Buffer.from([SIGHASH])]))
        .add(t.owner.toPublicKey().toBuffer()))
      const interp = new I()
      interp.verify(t.spend.inputs[0].script, t.lock, t.spend, 0, FLAGS, new BN(1)).should.equal(false)
    })
  })
})
