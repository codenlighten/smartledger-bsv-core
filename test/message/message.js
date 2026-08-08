'use strict'

const chai = require('chai')
const expect = chai.expect
const should = chai.should()

const bsv = require('../../')
const Address = bsv.Address
const Signature = bsv.crypto.Signature
const PrivateKey = bsv.PrivateKey
const Message = require('../../dist/message')

describe('Message', function () {
  const address = 'n1ZCYg9YXtB5XCZazLxSmPDa8iwJRZHhGx'
  const badAddress = 'mmRcrB5fTwgxaFJmVLNtaG8SV454y1E3kC'
  const privateKey = bsv.PrivateKey.fromWIF('cPBn5A4ikZvBTQ8D7NnvHZYCAxzDZ5Z2TSGW2LkyPiLxqYaJPBW4')
  const text = 'hello, world'
  const textBuffer = Buffer.from('hello, world')
  const bufferData = Buffer.from('H/DIn8uA1scAuKLlCx+/9LnAcJtwQQ0PmcPrJUq90aboLv3fH5fFvY+vmbfOSFEtGarznYli6ShPr9RXwY9UrIY=', 'base64')
  const signatureString = 'H/DIn8uA1scAuKLlCx+/9LnAcJtwQQ0PmcPrJUq90aboLv3fH5fFvY+vmbfOSFEtGarznYli6ShPr9RXwY9UrIY='

  const badSignatureString = 'H69qZ4mbZCcvXk7CWjptD5ypnYVLvQ3eMXLM8+1gX21SLH/GaFnAjQrDn37+TDw79i9zHhbiMMwhtvTwnPigZ6k='

  const signature = Signature.fromCompact(Buffer.from(signatureString, 'base64'))
  const badSignature = Signature.fromCompact(Buffer.from(badSignatureString, 'base64'))

  const publicKey = privateKey.toPublicKey()

  it('will error with incorrect message type', function () {
    expect(function () {
      return new Message(new Date())
    }).to.throw('First argument should be a string')
  })

  it('will instantiate without "new"', function () {
    const message = Message(text)
    should.exist(message)
  })

  let signature2
  let signature3

  it('can sign a message', function () {
    const message2 = new Message(text)
    signature2 = message2._sign(privateKey)
    signature3 = Message(text).sign(privateKey)
    should.exist(signature2)
    should.exist(signature3)
  })

  it('can sign a message (buffer representation of utf-8 string)', function () {
    const messageBuf = new Message(textBuffer)
    const signatureBuffer1 = messageBuf.sign(privateKey)
    const signatureBuffer2 = Message(textBuffer).sign(privateKey)
    should.exist(signatureBuffer1)
    should.exist(signatureBuffer2)
    const verified = messageBuf.verify(address, signatureBuffer1.toString()) && messageBuf.verify(address, signatureBuffer2.toString())
    verified.should.equal(true)
  })

  it('can sign a message (buffer representation of arbitrary data)', function () {
    const messageBuf = new Message(bufferData)
    const signatureBuffer1 = messageBuf.sign(privateKey)
    const signatureBuffer2 = Message(bufferData).sign(privateKey)
    should.exist(signatureBuffer1)
    should.exist(signatureBuffer2)
    const verified = messageBuf.verify(address, signatureBuffer1.toString()) && messageBuf.verify(address, signatureBuffer2.toString())
    verified.should.equal(true)
  })

  it('sign will error with incorrect private key argument', function () {
    expect(function () {
      const message3 = new Message(text)
      return message3.sign('not a private key')
    }).to.throw('First argument should be an instance of PrivateKey')
  })

  it('can verify a message with signature', function () {
    const message4 = new Message(text)
    const verified = message4._verify(publicKey, signature2)
    verified.should.equal(true)
  })

  it('can verify a message with existing signature', function () {
    const message5 = new Message(text)
    const verified = message5._verify(publicKey, signature)
    verified.should.equal(true)
  })

  it('verify will error with incorrect public key argument', function () {
    expect(function () {
      const message6 = new Message(text)
      return message6._verify('not a public key', signature)
    }).to.throw('First argument should be an instance of PublicKey')
  })

  it('verify will error with incorrect signature argument', function () {
    expect(function () {
      const message7 = new Message(text)
      return message7._verify(publicKey, 'not a signature')
    }).to.throw('Second argument should be an instance of Signature')
  })

  it('verify will correctly identify a bad signature', function () {
    const message8 = new Message(text)
    const verified = message8._verify(publicKey, badSignature)
    should.exist(message8.error)
    verified.should.equal(false)
  })

  it('can verify a message with address and generated signature string', function () {
    const message9 = new Message(text)
    const verified = message9.verify(address, signature3)
    should.not.exist(message9.error)
    verified.should.equal(true)
  })

  it('will not verify with address mismatch', function () {
    const message10 = new Message(text)
    const verified = message10.verify(badAddress, signatureString)
    should.exist(message10.error)
    verified.should.equal(false)
  })

  it('will verify with an uncompressed pubkey', function () {
    const privateKey = new bsv.PrivateKey('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss')
    const message = new Message('This is an example of a signed message.')
    const signature = message.sign(privateKey)
    const verified = message.verify(privateKey.toAddress(), signature)
    verified.should.equal(true)
  })

  it('can chain methods', function () {
    const verified = Message(text).verify(address, signatureString)
    verified.should.equal(true)
  })

  describe('@sign', function () {
    it('should sign and verify', function () {
      const privateKey = PrivateKey.fromString('L3nrwRssVKMkScjejmmu6kmq4hSuUApJnFdW1hGvBP69jnQuKYCh')
      const address = privateKey.toAddress()
      const message = 'this is the message that I want to sign'
      const sig = Message.sign(message, privateKey)
      sig.toString().should.equal('II5uoh3m0yQ+/5va+1acFQhPaEdTnFFiG/PiKpoC+kpgHbmIk3aWHQ6tyPGgNCUmKlSfwzcP6qVAxuUt0PwDzpg=')
      const verify = Message.verify(message, address, sig)
      verify.should.equal(true)
    })
  })

  describe('#json', function () {
    it('roundtrip to-from-to', function () {
      const json = new Message(text).toJSON()
      const message = Message.fromJSON(json)
      message.toString().should.equal(Buffer.from(text).toString())
    })

    it('checks that the string parameter is valid JSON', function () {
      expect(function () {
        return Message.fromJSON('¹')
      }).to.throw()
    })
  })

  describe('#toString', function () {
    it('message string', function () {
      const message = new Message(text)
      message.toString().should.equal(text)
    })

    it('roundtrip to-from-to', function () {
      const str = new Message(text).toString()
      const message = Message.fromString(str)
      message.toString().should.equal(text)
    })
  })

  describe('#inspect', function () {
    it('should output formatted output correctly', function () {
      const message = new Message(text)
      const output = '<Message: ' + text + '>'
      message.inspect().should.equal(output)
    })
  })

  it('accepts Address for verification', function () {
    const verified = Message(text)
      .verify(new Address(address), signatureString)
    verified.should.equal(true)
  })
})
