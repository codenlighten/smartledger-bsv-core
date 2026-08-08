'use strict'

const path = require('path')
const { TXS, SCRIPTS, KEYS } = require('../vectors')

// Bitcoin Core's sighash test vectors, as shipped with this repo.
// Row format: [rawTx, subscript, inputIndex, hashType, expectedHash]
// Row 0 is a header describing the columns.
const VECTORS = require(path.join(__dirname, '..', '..', 'test', 'data', 'sighash.json'))
  .slice(1)
  .filter((v) => v[4])

const hex = (s) => Buffer.from(s, 'hex')

// Every SIGHASH type, including the FORKID variants BSV requires and the
// ANYONECANPAY combinations.
const HASH_TYPES = [
  ['ALL', 0x01],
  ['NONE', 0x02],
  ['SINGLE', 0x03],
  ['ALL|ANYONECANPAY', 0x81],
  ['NONE|ANYONECANPAY', 0x82],
  ['SINGLE|ANYONECANPAY', 0x83],
  ['ALL|FORKID', 0x41],
  ['NONE|FORKID', 0x42],
  ['SINGLE|FORKID', 0x43],
  ['ALL|FORKID|ANYONECANPAY', 0xc1],
  ['NONE|FORKID|ANYONECANPAY', 0xc2],
  ['SINGLE|FORKID|ANYONECANPAY', 0xc3]
]

const cases = {
  // The whole Bitcoin Core corpus in one case. Kept as a single array so the
  // fixture stays compact; a mismatch still names the exact index.
  // Amount is passed as BN.Zero: these are pre-fork vectors with no value
  // committed, and the library requires an explicit amount rather than
  // defaulting one. Each row also records whether we match Core's expected
  // hash, so a disagreement is visible in the fixture itself.
  'bitcoind sighash vectors (all)': (bsv) => {
    const Script = bsv.Script
    const Transaction = bsv.Transaction
    const zero = bsv.crypto.BN.Zero
    return VECTORS.map((v, i) => {
      try {
        const tx = new Transaction(hex(v[0]))
        const subscript = new Script(hex(v[1]))
        const result = Transaction.sighash.sighash(tx, v[3], v[2], subscript, zero)
        const got = result.toString('hex')
        return `${i}:${got === v[4] ? 'match' : 'MISMATCH:' + got}`
      } catch (err) {
        return `${i}:threw:${err.name}`
      }
    })
  },

  'bitcoind vector count': () => VECTORS.length,

  // --- Per-hash-type coverage on a real transaction -----------------------
  ...HASH_TYPES.reduce((acc, [name, type]) => {
    acc[`sighash type ${name} on p2pkh spend`] = (bsv) => {
      const tx = new bsv.Transaction(TXS.p2pkhSpend)
      const subscript = bsv.Script.fromHex(SCRIPTS.p2pkh)
      return bsv.Transaction.sighash.sighash(
        tx, type, 0, subscript, new bsv.crypto.BN(1000)
      )
    }
    acc[`sighash preimage type ${name}`] = (bsv) => {
      const tx = new bsv.Transaction(TXS.p2pkhSpend)
      const subscript = bsv.Script.fromHex(SCRIPTS.p2pkh)
      return bsv.Transaction.sighash.sighashPreimage(
        tx, type, 0, subscript, new bsv.crypto.BN(1000)
      )
    }
    return acc
  }, {}),

  // --- Known-good anchor ---------------------------------------------------
  'coinbase sighash ALL (known constant)': (bsv) =>
    bsv.Transaction.sighash.sighash(
      new bsv.Transaction(TXS.coinbaseV2), 0x01, 0, bsv.Script.empty()
    ).toString('hex'),

  // --- Rejections ----------------------------------------------------------
  // FORKID sighash without a satoshi amount is unsatisfiable; it must throw
  // rather than compute a hash over an assumed zero value.
  'forkid sighash without amount is rejected': (bsv) =>
    bsv.Transaction.sighash.sighash(
      new bsv.Transaction(TXS.p2pkhSpend), 0x41, 0, bsv.Script.fromHex(SCRIPTS.p2pkh)
    ),
  'sighash with out-of-range input index': (bsv) =>
    bsv.Transaction.sighash.sighash(
      new bsv.Transaction(TXS.p2pkhSpend), 0x01, 99, bsv.Script.fromHex(SCRIPTS.p2pkh)
    ),
  // SIGHASH_SINGLE with no matching output is the notorious "return 1" bug in
  // the original client; whatever this library does, pin it.
  'sighash SINGLE with input index beyond outputs': (bsv) => {
    const tx = new bsv.Transaction(TXS.coinbaseV2)
    return bsv.Transaction.sighash.sighash(tx, 0x03, 0, bsv.Script.empty())
  },

  // --- sign/verify through the sighash layer -------------------------------
  'sighash sign and verify round-trip': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const tx = new bsv.Transaction(TXS.p2pkhSpend)
    const subscript = bsv.Script.buildPublicKeyHashOut(key.toAddress())
    const sig = bsv.Transaction.sighash.sign(
      tx, key, 0x41, 0, subscript, new bsv.crypto.BN(1000)
    )
    return {
      sig: sig.toString(),
      verifies: bsv.Transaction.sighash.verify(
        tx, sig, key.publicKey, 0, subscript, new bsv.crypto.BN(1000)
      ),
      wrongAmount: bsv.Transaction.sighash.verify(
        tx, sig, key.publicKey, 0, subscript, new bsv.crypto.BN(999)
      )
    }
  }
}

module.exports = { name: 'sighash', cases }
