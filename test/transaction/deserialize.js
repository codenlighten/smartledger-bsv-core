'use strict'

const Transaction = require('../../dist/transaction')

const vectorsValid = require('../data/bitcoind/tx_valid.json')
const vectorsInvalid = require('../data/bitcoind/tx_invalid.json')

describe('Transaction deserialization', function () {
  describe('valid transaction test case', function () {
    let index = 0
    vectorsValid.forEach(function (vector) {
      it('vector #' + index, function () {
        if (vector.length > 1) {
          const hexa = vector[1]
          Transaction(hexa).serialize(true).should.equal(hexa)
          index++
        }
      })
    })
  })
  describe('invalid transaction test case', function () {
    let index = 0
    vectorsInvalid.forEach(function (vector) {
      it('invalid vector #' + index, function () {
        if (vector.length > 1) {
          const hexa = vector[1]
          Transaction(hexa).serialize(true).should.equal(hexa)
          index++
        }
      })
    })
  })
})
