'use strict'

/* global describe, it */

// The OP_PUSH_TX vector from the sibling @smartledger/bsv, reproduced here.
//
// Both packages implement the same in-script signature construction (a = 1, k = 1, so r = Gx
// and P = 02||Gx), and "both implement it" is worth nothing unless something fails when they
// drift. This file is that something: the vector is an artifact built by bsv -- a locking
// script, a spending transaction, the grind nonce that made the s-value canonical, and the
// preimage -- and every assertion below RECOMPUTES a field from the others with this package's
// own code rather than comparing the file to itself.
//
// Measured when it was added: this package emits a byte-identical 377-byte locking script,
// reproduces the same preimage from the same transaction, accepts the same s-value, and
// verifies the bsv-built spend under its own interpreter. The file is deliberately a copy
// rather than a shared fixture, because a copy in each repository is what makes a future
// divergence fail a test instead of going unnoticed.

require('chai').should()
const bsv = require('../..')
const P = bsv.Covenant.PushTx
const H = bsv.Covenant.Helpers
const Hash = bsv.crypto.Hash
const V = require('../data/pushtx-authenticator-vector.json')

describe('OP_PUSH_TX vector from @smartledger/bsv', () => {
  it('emits a byte-identical locking script', () => {
    P.authenticator().toHex().should.equal(V.lockingScriptHex)
    bsv.Script.fromHex(V.lockingScriptHex).toBuffer().length.should.equal(V.lockingScriptBytes)
  })

  it('reproduces the preimage from the transaction, with this package\'s own helper', () => {
    const tx = new bsv.Transaction(V.spendTxHex)
    const lock = bsv.Script.fromHex(V.lockingScriptHex)
    H.rawPreimage(tx, 0, lock, V.inputSatoshis).toString('hex').should.equal(V.preimageHex)
    tx.nLockTime.should.equal(V.nLockTime, 'the grind nonce is part of the vector')
  })

  it('agrees on the digest and on the s-value condition', () => {
    const pre = Buffer.from(V.preimageHex, 'hex')
    Hash.sha256sha256(pre).toString('hex').should.equal(V.hash256OfPreimage)
    ;(!!P.sFromPreimage(pre)).should.equal(true)
  })

  it('verifies the sibling-built spend under this interpreter', () => {
    const tx = new bsv.Transaction(V.spendTxHex)
    const lock = bsv.Script.fromHex(V.lockingScriptHex)
    H.verify(tx.inputs[0].script, lock, { tx, satoshis: V.inputSatoshis }).ok.should.equal(true)
  })

  it('refuses a one-byte mutation of the preimage, which is what makes it a vector', () => {
    const tx = new bsv.Transaction(V.spendTxHex)
    const lock = bsv.Script.fromHex(V.lockingScriptHex)
    const pre = Buffer.from(V.preimageHex, 'hex')
    pre[0] ^= 0x01
    tx.inputs[0].setScript(new bsv.Script().add(pre))
    H.verify(tx.inputs[0].script, lock, { tx, satoshis: V.inputSatoshis }).ok.should.equal(false)
  })
})
