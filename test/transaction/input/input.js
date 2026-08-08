'use strict'

const should = require('chai').should()
const expect = require('chai').expect
const _ = require('../../../dist/util/_')

const bsv = require('../../..')
const errors = bsv.errors
const PrivateKey = bsv.PrivateKey
const Address = bsv.Address
const Script = bsv.Script
const Networks = bsv.Networks
const Input = bsv.Transaction.Input

describe('Transaction.Input', function () {
  const privateKey = new PrivateKey('KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4')
  const publicKey = privateKey.publicKey
  const address = new Address(publicKey, Networks.livenet)
  const output = {
    address: '33zbk2aSZYdNbRsMPPt6jgy6Kq1kQreqeb',
    prevTxId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  }
  const coinbase = {
    prevTxId: '0000000000000000000000000000000000000000000000000000000000000000',
    outputIndex: 0xFFFFFFFF,
    script: new Script(),
    satoshis: 1000000
  }

  const coinbaseJSON = JSON.stringify({
    prevTxId: '0000000000000000000000000000000000000000000000000000000000000000',
    outputIndex: 4294967295,
    script: ''
  })

  it('has abstract methods: "getSignatures", "isFullySigned", "addSignature", "clearSignatures"', function () {
    const input = new Input(output)
    _.each(['getSignatures', 'isFullySigned', 'addSignature', 'clearSignatures'], function (method) {
      expect(function () {
        return input[method]()
      }).to.throw(errors.AbstractMethodInvoked)
    })
  })
  it('detects coinbase transactions', function () {
    new Input(output).isNull().should.equal(false)
    const ci = new Input(coinbase)
    ci.isNull().should.equal(true)
  })

  describe('instantiation', function () {
    it('works without new', function () {
      const input = Input()
      should.exist(input)
    })
    it('fails with no script info', function () {
      expect(function () {
        const input = new Input({})
        input.toString()
      }).to.throw('Need a script to create an input')
    })
    it('fromObject should work', function () {
      const jsonData = JSON.parse(coinbaseJSON)
      const input = Input.fromObject(jsonData)
      should.exist(input)
      input.prevTxId.toString('hex').should.equal(jsonData.prevTxId)
      input.outputIndex.should.equal(jsonData.outputIndex)
    })
    it('fromObject should work', function () {
      const input = Input.fromObject(JSON.parse(coinbaseJSON))
      const obj = input.toObject()
      Input.fromObject(obj).should.deep.equal(input)
      obj.script = 42
      Input.fromObject.bind(null, obj).should.throw('Invalid argument type: script')
    })
  })

  it('_estimateSize returns correct size', function () {
    const input = new Input(output)
    input._estimateSize().should.equal(66)
  })

  it('defaults isFinal correctly', function () {
    new Input(output).isFinal().should.equal(true)
  })

  it('handles isFinal when sequence number is set to non default value', function () {
    new Input({ ...output, sequenceNumber: 0 }).isFinal().should.equal(false)
  })
})
