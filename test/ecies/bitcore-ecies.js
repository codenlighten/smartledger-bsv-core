'use strict'

const ECIES = require('../../lib/ecies/bitcore-ecies')

const should = require('chai').should()
const bsv = require('../../')
const PrivateKey = bsv.PrivateKey

const aliceKey = new PrivateKey('L1Ejc5dAigm5XrM3mNptMEsNnHzS7s51YxU7J61ewGshZTKkbmzJ')
const bobKey = new PrivateKey('KxfxrUXSMjJQcb3JgnaaA6MqsrKQ1nBSxvhuigdKRyFiEm6BZDgG')

describe('Bitcore ECIES', function () {
  it('should exist', function () {
    should.exist(ECIES)
  })

  it('constructor', function () {
    (typeof ECIES).should.equal('function')
  })

  it('constructs an instance', function () {
    const ecies = new ECIES();
    (ecies instanceof ECIES).should.equal(true)
  })

  it('doesnt require the "new" keyword', function () {
    const ecies = ECIES();
    (ecies instanceof ECIES).should.equal(true)
  })

  // Regression: the no-`new` factory path used to drop opts (return new ECIES()),
  // silently ignoring { noKey, shortTag } and changing the wire format.
  it('forwards opts through the no-"new" factory path', function () {
    const ecies = ECIES({ noKey: true, shortTag: true })
    ecies.opts.noKey.should.equal(true)
    ecies.opts.shortTag.should.equal(true)
  })

  it('privateKey fails with no argument', function () {
    const ecies = ECIES()
    const fail = function () {
      ecies.privateKey()
    }
    fail.should.throw('no private key provided')
  })

  it('chainable function', function () {
    const ecies = ECIES()
      .privateKey(aliceKey)
      .publicKey(bobKey.publicKey);

    (ecies instanceof ECIES).should.equal(true)
  })

  const alice = ECIES()
    .privateKey(aliceKey)
    .publicKey(bobKey.publicKey)

  const bob = ECIES()
    .privateKey(bobKey)
    .publicKey(aliceKey.publicKey)

  const message = 'attack at dawn'
  const encrypted = '0339e504d6492b082da96e11e8f039796b06cd4855c101e2492a6f10f3e056a9e712c732611c6917ab5c57a1926973bc44a1586e94a783f81d05ce72518d9b0a80e2e13c7ff7d1306583f9cc7a48def5b37fbf2d5f294f128472a6e9c78dede5f5'
  const encBuf = Buffer.from(encrypted, 'hex')

  it('correctly encrypts a message', function () {
    const ciphertext = alice.encrypt(message)
    Buffer.isBuffer(ciphertext).should.equal(true)
    ciphertext.toString('hex').should.equal(encrypted)
  })

  it('correctly decrypts a message', function () {
    const decrypted = bob
      .decrypt(encBuf)
      .toString()
    decrypted.should.equal(message)
  })

  it('retrieves senders publickey from the encypted buffer', function () {
    const bob2 = ECIES().privateKey(bobKey)
    const decrypted = bob2.decrypt(encBuf).toString()
    bob2._publicKey.toDER().should.deep.equal(aliceKey.publicKey.toDER())
    decrypted.should.equal(message)
  })

  it('roundtrips', function () {
    const secret = 'some secret message!!!'
    const encrypted = alice.encrypt(secret)
    const decrypted = bob
      .decrypt(encrypted)
      .toString()
    decrypted.should.equal(secret)
  })

  it('roundtrips (no public key)', function () {
    alice.opts.noKey = true
    bob.opts.noKey = true
    const secret = 'some secret message!!!'
    const encrypted = alice.encrypt(secret)
    const decrypted = bob
      .decrypt(encrypted)
      .toString()
    decrypted.should.equal(secret)
  })

  it('roundtrips (short tag)', function () {
    alice.opts.shortTag = true
    bob.opts.shortTag = true
    const secret = 'some secret message!!!'
    const encrypted = alice.encrypt(secret)
    const decrypted = bob
      .decrypt(encrypted)
      .toString()
    decrypted.should.equal(secret)
  })

  it('roundtrips (no public key & short tag)', function () {
    alice.opts.noKey = true
    alice.opts.shortTag = true
    bob.opts.noKey = true
    bob.opts.shortTag = true
    const secret = 'some secret message!!!'
    const encrypted = alice.encrypt(secret)
    const decrypted = bob
      .decrypt(encrypted)
      .toString()
    decrypted.should.equal(secret)
  })

  it('correctly fails if trying to decrypt a bad message', function () {
    const encrypted = Buffer.from(encBuf)
    encrypted[encrypted.length - 1] = 2;
    (function () {
      return bob.decrypt(encrypted)
    }).should.throw('Invalid checksum')
  })

  it('decrypting uncompressed keys', function () {
    const secret = 'test'

    // test uncompressed
    const alicePrivateKey = bsv.PrivateKey.fromObject({
      bn: '1fa76f9c799ca3a51e2c7c901d3ba8e24f6d870beccf8df56faf30120b38f360',
      compressed: false,
      network: 'livenet'
    })
    const alicePublicKey = bsv.PublicKey.fromPrivateKey(alicePrivateKey) // alicePrivateKey.publicKey
    alicePrivateKey.compressed.should.equal(false)

    const cypher1 = ECIES().privateKey(alicePrivateKey).publicKey(alicePublicKey)
    const encrypted = cypher1.encrypt(secret)

    const cypher2 = ECIES().privateKey(alicePrivateKey).publicKey(alicePublicKey)
    const decrypted = cypher2.decrypt(encrypted)
    secret.should.equal(decrypted.toString())
  })

  it('decrypting compressed keys', function () {
    const secret = 'test'

    // test compressed
    const alicePrivateKey = bsv.PrivateKey.fromObject({
      bn: '1fa76f9c799ca3a51e2c7c901d3ba8e24f6d870beccf8df56faf30120b38f360',
      compressed: true,
      network: 'livenet'
    })
    const alicePublicKey = bsv.PublicKey.fromPrivateKey(alicePrivateKey) // alicePrivateKey.publicKey
    alicePrivateKey.compressed.should.equal(true)

    const cypher1 = ECIES().privateKey(alicePrivateKey).publicKey(alicePublicKey)
    const encrypted = cypher1.encrypt(secret)

    const cypher2 = ECIES().privateKey(alicePrivateKey).publicKey(alicePublicKey)
    const decrypted = cypher2.decrypt(encrypted)
    secret.should.equal(decrypted.toString())
  })
})
