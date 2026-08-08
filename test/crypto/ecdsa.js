'use strict'

const ECDSA = require('../../dist/crypto/ecdsa')
const Hash = require('../../dist/crypto/hash')
const Privkey = require('../../dist/privatekey')
const Pubkey = require('../../dist/publickey')
const Signature = require('../../dist/crypto/signature')
const BN = require('../../dist/crypto/bn')
const point = require('../../dist/crypto/point')
const should = require('chai').should()
const vectors = require('../data/ecdsa')

describe('ECDSA', function () {
  it('instantiation', function () {
    const ecdsa = new ECDSA()
    should.exist(ecdsa)
  })

  const ecdsa = new ECDSA()
  ecdsa.hashbuf = Hash.sha256(Buffer.from('test data'))
  ecdsa.privkey = new Privkey(BN.fromBuffer(
    Buffer.from('fee0a1f7afebf9d2a5a80c0c98a31c709681cce195cbcd06342b517970c0be1e', 'hex')
  ))
  ecdsa.privkey2pubkey()

  describe('#set', function () {
    it('sets hashbuf', function () {
      should.exist(ECDSA().set({
        hashbuf: ecdsa.hashbuf
      }).hashbuf)
    })
  })

  describe('#calci', function () {
    it('calculates i correctly', function () {
      ecdsa.randomK()
      ecdsa.sign()
      ecdsa.calci()
      should.exist(ecdsa.sig.i)
    })

    it('calulates this known i', function () {
      const hashbuf = Hash.sha256(Buffer.from('some data'))
      const r = new BN('71706645040721865894779025947914615666559616020894583599959600180037551395766', 10)
      const s = new BN('109412465507152403114191008482955798903072313614214706891149785278625167723646', 10)
      const ecdsa = new ECDSA({
        privkey: new Privkey(BN.fromBuffer(Hash.sha256(Buffer.from('test')))),
        hashbuf,
        sig: new Signature({
          r,
          s
        })
      })

      ecdsa.calci()
      ecdsa.sig.i.should.equal(1)
    })
  })

  describe('#fromString', function () {
    it('round trip with fromString', function () {
      const str = ecdsa.toString()
      const ecdsa2 = ECDSA.fromString(str)
      should.exist(ecdsa2.hashbuf)
      should.exist(ecdsa2.privkey)
    })
  })

  describe('#randomK', function () {
    it('should generate a new random k when called twice in a row', function () {
      ecdsa.randomK()
      const k1 = ecdsa.k
      ecdsa.randomK()
      const k2 = ecdsa.k;
      (k1.cmp(k2) === 0).should.equal(false)
    })

    it('should generate a random k that is (almost always) greater than this relatively small number', function () {
      ecdsa.randomK()
      const k1 = ecdsa.k
      const k2 = new BN(Math.pow(2, 32)).mul(new BN(Math.pow(2, 32))).mul(new BN(Math.pow(2, 32)))
      k2.gt(k1).should.equal(false)
    })
  })

  describe('#deterministicK', function () {
    it('should generate the same deterministic k', function () {
      ecdsa.deterministicK()
      ecdsa.k.toBuffer().toString('hex')
        .should.equal('fcce1de7a9bcd6b2d3defade6afa1913fb9229e3b7ddf4749b55c4848b2a196e')
    })
    it('should generate the same deterministic k if badrs is set', function () {
      ecdsa.deterministicK(0)
      ecdsa.k.toBuffer().toString('hex')
        .should.equal('fcce1de7a9bcd6b2d3defade6afa1913fb9229e3b7ddf4749b55c4848b2a196e')
      ecdsa.deterministicK(1)
      ecdsa.k.toBuffer().toString('hex')
        .should.not.equal('fcce1de7a9bcd6b2d3defade6afa1913fb9229e3b7ddf4749b55c4848b2a196e')
      ecdsa.k.toBuffer().toString('hex')
        .should.equal('727fbcb59eb48b1d7d46f95a04991fc512eb9dbf9105628e3aec87428df28fd8')
    })
    it('should compute this test vector correctly', function () {
      // test fixture from bitcoinjs
      // https://github.com/bitcoinjs/bitcoinjs-lib/blob/10630873ebaa42381c5871e20336fbfb46564ac8/test/fixtures/ecdsa.json#L6
      const ecdsa = new ECDSA()
      ecdsa.hashbuf = Hash.sha256(Buffer.from('Everything should be made as simple as possible, but not simpler.'))
      ecdsa.privkey = new Privkey(new BN(1))
      ecdsa.privkey2pubkey()
      ecdsa.deterministicK()
      ecdsa.k.toBuffer().toString('hex')
        .should.equal('ec633bd56a5774a0940cb97e27a9e4e51dc94af737596a0c5cbb3d30332d92a5')
      ecdsa.sign()
      ecdsa.sig.r.toString()
        .should.equal('23362334225185207751494092901091441011938859014081160902781146257181456271561')
      ecdsa.sig.s.toString()
        .should.equal('50433721247292933944369538617440297985091596895097604618403996029256432099938')
    })
  })

  describe('nonce reuse', function () {
    // Signing two different messages under one nonce reveals the private key.
    const N = point.getN()
    const h1 = Hash.sha256(Buffer.from('pay alice 1 coin'))
    const h2 = Hash.sha256(Buffer.from('pay bob 2 coins'))

    const freshSigner = function () {
      return ECDSA().set({
        privkey: new Privkey(BN.fromBuffer(Buffer.from(
          'fee0a1f7afebf9d2a5a80c0c98a31c709681cce195cbcd06342b517970c0be1e', 'hex')))
      })
    }

    it('does not reuse k when one instance signs two different messages', function () {
      const e = freshSigner()
      const sig1 = e.set({ hashbuf: h1 }).sign().sig
      const k1 = e.k
      const sig2 = e.set({ hashbuf: h2 }).sign().sig
      const k2 = e.k;
      (k1.cmp(k2) === 0).should.equal(false)
      sig1.r.eq(sig2.r).should.equal(false)
    })

    it('does not reuse k across signRandomK calls on one instance', function () {
      const e = freshSigner()
      const sig1 = e.set({ hashbuf: h1 }).signRandomK().sig
      const sig2 = e.set({ hashbuf: h2 }).sign().sig
      sig1.r.eq(sig2.r).should.equal(false)
    })

    it('does not leak the private key from two signatures by one instance', function () {
      const e = freshSigner()
      const d = e.privkey.bn
      const sig1 = e.set({ hashbuf: h1 }).sign().sig
      const sig2 = e.set({ hashbuf: h2 }).sign().sig

      // toLowS may have flipped either s, so try every sign combination.
      const red = BN.red(N)
      const inv = function (x) { return x.toRed(red).redInvm().fromRed() }
      const mul = function (a, b) { return a.toRed(red).redMul(b.toRed(red)).fromRed() }
      const e1 = BN.fromBuffer(h1)
      const e2 = BN.fromBuffer(h2)
      let recovered = false
      ;[1, -1].forEach(function (f1) {
        ;[1, -1].forEach(function (f2) {
          const S1 = f1 === 1 ? sig1.s : N.sub(sig1.s)
          const S2 = f2 === 1 ? sig2.s : N.sub(sig2.s)
          const diff = S1.sub(S2).umod(N)
          if (diff.isZero()) return
          const k = mul(e1.sub(e2).umod(N), inv(diff))
          const guess = mul(S1.mul(k).umod(N).sub(e1).umod(N), inv(sig1.r))
          if (guess.toString(16) === d.toString(16)) recovered = true
        })
      })
      recovered.should.equal(false)
    })

    it('still honours an explicitly supplied k for a single signature', function () {
      const k = new BN('114860389168127852803919605627759231199925249596762615988727970217268189974335', 10)
      const a = freshSigner().set({ hashbuf: h1, k })
      const b = freshSigner().set({ hashbuf: h1, k })
      a.sign().sig.r.eq(b.sign().sig.r).should.equal(true)
      a.k.eq(k).should.equal(true)
    })

    it('signs the same message deterministically across instances', function () {
      const a = freshSigner().set({ hashbuf: h1 }).sign().sig
      const b = freshSigner().set({ hashbuf: h1 }).sign().sig
      a.r.eq(b.r).should.equal(true)
      a.s.eq(b.s).should.equal(true)
    })
  })

  describe('#toPublicKey', function () {
    it('should calculate the correct public key', function () {
      ecdsa.k = new BN('114860389168127852803919605627759231199925249596762615988727970217268189974335', 10)
      ecdsa.sign()
      ecdsa.sig.i = 0
      const pubkey = ecdsa.toPublicKey()
      pubkey.point.eq(ecdsa.pubkey.point).should.equal(true)
    })

    it('should calculate the correct public key for this signature with low s', function () {
      ecdsa.k = new BN('114860389168127852803919605627759231199925249596762615988727970217268189974335', 10)
      ecdsa.sig = Signature.fromString('3045022100ec3cfe0e335791ad278b4ec8eac93d0347' +
        'a97877bb1d54d35d189e225c15f6650220278cf15b05ce47fb37d2233802899d94c774d5480bba9f0f2d996baa13370c43')
      ecdsa.sig.i = 0
      const pubkey = ecdsa.toPublicKey()
      pubkey.point.eq(ecdsa.pubkey.point).should.equal(true)
    })

    it('should calculate the correct public key for this signature with high s', function () {
      ecdsa.k = new BN('114860389168127852803919605627759231199925249596762615988727970217268189974335', 10)
      ecdsa.sign()
      ecdsa.sig = Signature.fromString('3046022100ec3cfe0e335791ad278b4ec8eac93d0347' +
        'a97877bb1d54d35d189e225c15f665022100d8730ea4fa31b804c82ddcc7fd766269f33a079ea38e012c9238f2e2bcff34fe')
      ecdsa.sig.i = 1
      const pubkey = ecdsa.toPublicKey()
      pubkey.point.eq(ecdsa.pubkey.point).should.equal(true)
    })
  })

  describe('#sigError', function () {
    it('should return an error if the hash is invalid', function () {
      const ecdsa = new ECDSA()
      ecdsa.sigError().should.equal('hashbuf must be a 32 byte buffer')
    })

    it('should return an error if r, s are invalid', function () {
      const ecdsa = new ECDSA()
      ecdsa.hashbuf = Hash.sha256(Buffer.from('test'))
      const pk = Pubkey.fromDER(Buffer.from('041ff0fe0f7b15ffaa85ff9f4744d539139c252a49' +
        '710fb053bb9f2b933173ff9a7baad41d04514751e6851f5304fd243751703bed21b914f6be218c0fa354a341', 'hex'))
      ecdsa.pubkey = pk
      ecdsa.sig = new Signature()
      ecdsa.sig.r = new BN(0)
      ecdsa.sig.s = new BN(0)
      ecdsa.sigError().should.equal('r and s not in range')
    })

    it('should return an error if the signature is incorrect', function () {
      ecdsa.sig = Signature.fromString('3046022100e9915e6236695f093a4128ac2a956c40' +
        'ed971531de2f4f41ba05fac7e2bd019c02210094e6a4a769cc7f2a8ab3db696c7cd8d56bcdbfff860a8c81de4bc6a798b90827')
      ecdsa.sig.r = ecdsa.sig.r.add(new BN(1))
      ecdsa.sigError().should.equal('Invalid signature')
    })
  })

  describe('#sign', function () {
    it('should create a valid signature', function () {
      ecdsa.randomK()
      ecdsa.sign()
      ecdsa.verify().should.equal(true)
    })

    it('should should throw an error if hashbuf is not 32 bytes', function () {
      const ecdsa2 = ECDSA().set({
        hashbuf: ecdsa.hashbuf.slice(0, 31),
        privkey: ecdsa.privkey
      })
      ecdsa2.randomK()
      ecdsa2.sign.bind(ecdsa2).should.throw('hashbuf must be a 32 byte buffer')
    })

    it('should default to deterministicK', function () {
      const ecdsa2 = new ECDSA(ecdsa)
      ecdsa2.k = undefined
      let called = 0
      const deterministicK = ecdsa2.deterministicK.bind(ecdsa2)
      ecdsa2.deterministicK = function () {
        deterministicK()
        called++
      }
      ecdsa2.sign()
      called.should.equal(1)
    })

    it('should generate right K', function () {
      const msg1 = Buffer.from('52204d20fd0131ae1afd173fd80a3a746d2dcc0cddced8c9dc3d61cc7ab6e966', 'hex')
      const msg2 = [].reverse.call(Buffer.from(msg1))
      const pk = Buffer.from('16f243e962c59e71e54189e67e66cf2440a1334514c09c00ddcc21632bac9808', 'hex')
      const signature1 = ECDSA.sign(msg1, Privkey.fromBuffer(pk)).toBuffer().toString('hex')
      const signature2 = ECDSA.sign(msg2, Privkey.fromBuffer(pk), 'little').toBuffer().toString('hex')
      signature1.should.equal(signature2)
    })
  })

  describe('#toString', function () {
    it('should convert this to a string', function () {
      const str = ecdsa.toString();
      (typeof str === 'string').should.equal(true)
    })
  })

  describe('signing and verification', function () {
    describe('@sign', function () {
      it('should produce a signature', function () {
        const sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey)
        ;(sig instanceof Signature).should.equal(true)
      })

      it('should produce a signaturei', function () {
        const sig = ECDSA.signWithCalcI(ecdsa.hashbuf, ecdsa.privkey)
        ;(sig instanceof Signature).should.equal(true)
        should.exist(sig.i)
        sig.toCompact().toString('base64').should.equal('IF7ucRrxMczOWYg28NkA+krY4aXx9XgT7KVglwpLEqqyIUtqBrrU5mSDQqOm0ETZ47KdQEMv121aWkxO7P1hbGk=')
      })

      it('should produce a signature', function () {
        const sig = ECDSA.signRandomK(ecdsa.hashbuf, ecdsa.privkey)
        ;(sig instanceof Signature).should.equal(true)
        const sig2 = ECDSA.signRandomK(ecdsa.hashbuf, ecdsa.privkey)
        ;(sig2 instanceof Signature).should.equal(true)
        sig.toString().should.not.equal(sig2.toString())
      })

      it('should produce a signature, and be different when called twice', function () {
        ecdsa.signRandomK()
        should.exist(ecdsa.sig)
        const ecdsa2 = ECDSA(ecdsa)
        ecdsa2.signRandomK()
        ecdsa.sig.toString().should.not.equal(ecdsa2.sig.toString())
      })
    })

    describe('#verify', function () {
      it('should verify a signature that was just signed', function () {
        ecdsa.sig = Signature.fromString('3046022100e9915e6236695f093a4128ac2a956c' +
          '40ed971531de2f4f41ba05fac7e2bd019c02210094e6a4a769cc7f2a8ab3db696c7cd8d56bcdbfff860a8c81de4bc6a798b90827')
        ecdsa.verify().should.equal(true)
      })
      // 7.0: verify() returns a strict boolean, not the (always-truthy) instance.
      // A forged signature must be REJECTED by `if (ecdsa.verify())`, which was the
      // whole point of removing the trap.
      it('returns a strict boolean, not the instance (7.0 trap closed)', function () {
        ecdsa.signRandomK()
        const result = ecdsa.verify()
        result.should.be.a('boolean')
        result.should.equal(true)
        // Forge the signature: the return value itself must be falsy.
        const forged = new ECDSA()
        forged.hashbuf = ecdsa.hashbuf
        forged.pubkey = ecdsa.pubkey
        forged.sig = new Signature(ecdsa.sig.r.add(new BN(1)), ecdsa.sig.s)
        forged.verify().should.equal(false)
        ;(!!forged.verify()).should.equal(false) // `if (forged.verify())` does NOT enter
      })
      it('verifyBool() remains a strict-boolean alias', function () {
        ecdsa.signRandomK()
        ecdsa.verifyBool().should.equal(true)
        const forged = new ECDSA()
        forged.hashbuf = ecdsa.hashbuf
        forged.pubkey = ecdsa.pubkey
        forged.sig = new Signature(ecdsa.sig.r.add(new BN(1)), ecdsa.sig.s)
        forged.verifyBool().should.equal(false)
      })
      it('should verify this known good signature', function () {
        ecdsa.signRandomK()
        ecdsa.verify().should.equal(true)
      })
      it('should verify a valid signature, and unverify an invalid signature', function () {
        const sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey)
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey).should.equal(true)
        const fakesig = new Signature(sig.r.add(new BN(1)), sig.s)
        ECDSA.verify(ecdsa.hashbuf, fakesig, ecdsa.pubkey).should.equal(false)
      })
      it('should work with big and little endian', function () {
        let sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey, 'big')
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'big').should.equal(true)
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'little').should.equal(false)
        sig = ECDSA.sign(ecdsa.hashbuf, ecdsa.privkey, 'little')
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'big').should.equal(false)
        ECDSA.verify(ecdsa.hashbuf, sig, ecdsa.pubkey, 'little').should.equal(true)
      })
    })

    describe('vectors', function () {
      vectors.valid.forEach(function (obj, i) {
        it('should validate valid vector ' + i, function () {
          const ecdsa = ECDSA().set({
            privkey: new Privkey(BN.fromBuffer(Buffer.from(obj.d, 'hex'))),
            k: BN.fromBuffer(Buffer.from(obj.k, 'hex')),
            hashbuf: Hash.sha256(Buffer.from(obj.message)),
            sig: new Signature().set({
              r: new BN(obj.signature.r),
              s: new BN(obj.signature.s),
              i: obj.i
            })
          })
          const ecdsa2 = ECDSA(ecdsa)
          ecdsa2.k = undefined
          ecdsa2.sign()
          ecdsa2.calci()
          ecdsa2.k.toString().should.equal(ecdsa.k.toString())
          ecdsa2.sig.toString().should.equal(ecdsa.sig.toString())
          ecdsa2.sig.i.should.equal(ecdsa.sig.i)
          ecdsa.verify().should.equal(true)
        })
      })

      vectors.invalid.sigError.forEach(function (obj, i) {
        it('should validate invalid.sigError vector ' + i + ': ' + obj.description, function () {
          const ecdsa = ECDSA().set({
            pubkey: Pubkey.fromPoint(point.fromX(true, 1)),
            sig: new Signature(new BN(obj.signature.r), new BN(obj.signature.s)),
            hashbuf: Hash.sha256(Buffer.from(obj.message))
          })
          ecdsa.sigError().should.equal(obj.exception)
        })
      })

      vectors.deterministicK.forEach(function (obj, i) {
        it('should validate deterministicK vector ' + i, function () {
          const hashbuf = Hash.sha256(Buffer.from(obj.message))
          const privkey = Privkey(BN.fromBuffer(Buffer.from(obj.privkey, 'hex')), 'mainnet')
          const ecdsa = ECDSA({
            privkey,
            hashbuf
          })
          ecdsa.deterministicK(0).k.toString('hex').should.equal(obj.k_bad00)
          ecdsa.deterministicK(1).k.toString('hex').should.equal(obj.k_bad01)
          ecdsa.deterministicK(15).k.toString('hex').should.equal(obj.k_bad15)
        })
      })
    })
  })
})
