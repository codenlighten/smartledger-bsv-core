'use strict'

const { TXS, KEYS, ADDRESSES, SCRIPTS } = require('../vectors')

const cases = {}

// --- Parse / re-serialize ---------------------------------------------------
for (const [name, raw] of Object.entries(TXS)) {
  cases[`parse ${name}`] = (bsv) => {
    const tx = new bsv.Transaction(raw)
    return {
      id: tx.id,
      hash: tx.hash,
      version: tx.version,
      nLockTime: tx.nLockTime,
      inputCount: tx.inputs.length,
      outputCount: tx.outputs.length,
      outputAmount: tx.outputAmount,
      isCoinbase: tx.isCoinbase(),
      size: tx.toBuffer().length,
      roundTrips: tx.uncheckedSerialize() === raw
    }
  }
  cases[`toObject ${name}`] = (bsv) => new bsv.Transaction(raw).toObject()
}

Object.assign(cases, {
  // --- Building -------------------------------------------------------------
  // A fully deterministic build: fixed utxo, fixed key, fixed fee.
  'build and sign p2pkh': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const utxo = {
      txId: '0'.repeat(64),
      outputIndex: 0,
      address: key.toAddress().toString(),
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 100000
    }
    const tx = new bsv.Transaction()
      .from(utxo)
      .to(ADDRESSES.mainnetP2PKH, 90000)
      .fee(1000)
      .change(key.toAddress())
      .sign(key)
    return {
      hex: tx.uncheckedSerialize(),
      id: tx.id,
      fullySigned: tx.isFullySigned(),
      verified: tx.verify(),
      inputAmount: tx.inputAmount,
      outputAmount: tx.outputAmount,
      fee: tx.getFee()
    }
  },

  'signing is deterministic': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const utxo = {
      txId: '0'.repeat(64),
      outputIndex: 0,
      address: key.toAddress().toString(),
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 100000
    }
    const build = () => new bsv.Transaction().from(utxo)
      .to(ADDRESSES.mainnetP2PKH, 90000).fee(1000).sign(key).uncheckedSerialize()
    const first = build()
    const second = build()
    return { stable: first === second }
  },

  'build with OP_RETURN data': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const utxo = {
      txId: '1'.repeat(64),
      outputIndex: 0,
      address: key.toAddress().toString(),
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 50000
    }
    const tx = new bsv.Transaction().from(utxo).addSafeData('conformance').sign(key)
    return { hex: tx.uncheckedSerialize(), outputs: tx.outputs.length }
  },

  // --- Fee and dust behavior ------------------------------------------------
  'feePerKb affects fee': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const utxo = {
      txId: '2'.repeat(64),
      outputIndex: 0,
      address: key.toAddress().toString(),
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 1000000
    }
    return [1, 50, 500].map((rate) => {
      const tx = new bsv.Transaction().from(utxo)
        .to(ADDRESSES.mainnetP2PKH, 500000).feePerKb(rate).change(key.toAddress())
      return { rate, fee: tx.getFee(), estimatedSize: tx._estimateSize() }
    })
  },

  // --- Serialization safety -------------------------------------------------
  // checkedSerialize refuses to emit a transaction with a detected problem.
  // Which problems it detects is exactly what we need pinned.
  'checkedSerialize on unsigned tx': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const utxo = {
      txId: '3'.repeat(64),
      outputIndex: 0,
      address: key.toAddress().toString(),
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 100000
    }
    return new bsv.Transaction().from(utxo).to(ADDRESSES.mainnetP2PKH, 90000).checkedSerialize({})
  },
  'serialization error on dust output': (bsv) => {
    const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
    const utxo = {
      txId: '4'.repeat(64),
      outputIndex: 0,
      address: key.toAddress().toString(),
      script: bsv.Script.buildPublicKeyHashOut(key.toAddress()).toHex(),
      satoshis: 100000
    }
    const tx = new bsv.Transaction().from(utxo).to(ADDRESSES.mainnetP2PKH, 1).sign(key)
    return { error: tx.getSerializationError({}) && tx.getSerializationError({}).message }
  },
  'invalidSatoshis detection': (bsv) => {
    const tx = new bsv.Transaction()
    tx.addOutput(new bsv.Transaction.Output({ script: bsv.Script.fromHex(SCRIPTS.p2pkh), satoshis: 0 }))
    return tx.invalidSatoshis()
  },
  'output rejects negative satoshis': (bsv) =>
    new bsv.Transaction.Output({ script: bsv.Script.fromHex(SCRIPTS.p2pkh), satoshis: -1 }),
  'output rejects fractional satoshis': (bsv) =>
    new bsv.Transaction.Output({ script: bsv.Script.fromHex(SCRIPTS.p2pkh), satoshis: 1.5 }),

  // --- Locktime -------------------------------------------------------------
  lockUntilBlockHeight: (bsv) => {
    const tx = new bsv.Transaction().lockUntilBlockHeight(400000)
    return { nLockTime: tx.nLockTime, getLockTime: tx.getLockTime() }
  },
  'lockUntilBlockHeight above threshold rejected': (bsv) =>
    new bsv.Transaction().lockUntilBlockHeight(500000000),
  lockUntilDate: (bsv) => {
    const tx = new bsv.Transaction().lockUntilDate(new Date('2030-01-01T00:00:00Z'))
    return { nLockTime: tx.nLockTime }
  },

  // --- Sorting (BIP69) ------------------------------------------------------
  'BIP69 sort is stable': (bsv) => {
    const tx = new bsv.Transaction(TXS.p2pkhSpend)
    const before = tx.uncheckedSerialize()
    const after = tx.sort().uncheckedSerialize()
    return { changed: before !== after, after }
  },

  // --- Malformed input ------------------------------------------------------
  'parse truncated tx': (bsv) => new bsv.Transaction(TXS.p2pkhSpend.slice(0, 40)),
  'parse empty hex': (bsv) => new bsv.Transaction(''),
  'parse odd-length hex': (bsv) => new bsv.Transaction('0100000'),
  'parse tx with trailing bytes': (bsv) => new bsv.Transaction(TXS.p2pkhSpend + 'deadbeef'),
  'parse garbage': (bsv) => new bsv.Transaction('ffffffffffffffff'),

  // --- Input / Output primitives -------------------------------------------
  'output round-trip': (bsv) => {
    const o = new bsv.Transaction.Output({ script: bsv.Script.fromHex(SCRIPTS.p2pkh), satoshis: 12345 })
    return { hex: o.toBufferWriter().toBuffer(), obj: o.toObject(), size: o.getSize() }
  },
  'input toObject': (bsv) => new bsv.Transaction(TXS.p2pkhSpend).inputs[0].toObject(),
  'coinbase input detection': (bsv) => ({
    coinbase: new bsv.Transaction(TXS.block1Coinbase).isCoinbase(),
    spend: new bsv.Transaction(TXS.p2pkhSpend).isCoinbase()
  })
})

module.exports = { name: 'transaction', cases }
