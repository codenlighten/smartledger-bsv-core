'use strict'

/* global describe, it, before, after */

// OrdLock marketplace covenant — list a 1Sat ordinal for sale behind a trustless
// "pay the seller or cancel" covenant. Every locking/unlocking pair below is driven
// through the consensus interpreter (the "if it emits Script, it's interpreter-
// verified" operating principle), including adversarial spends that MUST be rejected.

require('chai').should()
const bsv = require('../..')
const Ord = bsv.Ordinals
const SC = bsv.Covenant.Helpers
const Script = bsv.Script
const PrivateKey = bsv.PrivateKey
const Transaction = bsv.Transaction

const help = SC
const verify = help.verify
const p2pkhOutput = help.p2pkhOutput

const ORD_SATS = 1
const PRICE = 100000

describe('Ordinals OrdLock marketplace', function () {
  this.timeout(20000)
  const I = bsv.Script.Interpreter
  let saved

  before(function () {
    saved = I.getLimits()
    SC.enableGenesis()
  })
  after(function () {
    I.setLimits(saved)
  })

  const seller = PrivateKey.fromRandom()
  const buyer = PrivateKey.fromRandom()

  // A funding tx that pays the listing UTXO, plus a spend consuming it at input 0.
  function fundListing (lock) {
    return help.fundAndSpend(lock, ORD_SATS, {}).spend
  }

  // Build the buyer's outputs: [ ordinal->buyer (index 0), payment->seller (index 1) ].
  function buyerOutputs (payTo, price) {
    return [
      p2pkhOutput(buyer, ORD_SATS), // the ordinal goes to the buyer at output 0
      Ord.payOutputFor(payTo || seller, price == null ? PRICE : price) // seller payment at 1
    ]
  }

  it('verifies a purchase that pays the seller', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    buyerOutputs().forEach(function (o) { spend.addOutput(o) })
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('stays valid when the buyer adds a funding input and a change output', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    // outputs: [ordinal->buyer, payment->seller, change->buyer]
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE))
    spend.addOutput(p2pkhOutput(buyer, 40000)) // buyer change, trailing

    // Grind + build the unlock BEFORE adding the (ANYONECANPAY) funding input.
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    spend.addInput(new Transaction.Input({
      prevTxId: '22'.repeat(32), outputIndex: 0, script: Script.empty()
    }), p2pkhOutput(buyer, PRICE + 50000).script, PRICE + 50000)

    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('rejects a purchase that underpays the seller', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE))
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })

    // Tamper: shave the seller's payment after grinding → committed outputs change.
    spend.outputs[1] = Ord.payOutputFor(seller, PRICE - 1)
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(false)
  })

  it('rejects a purchase that redirects the payment to someone else', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE))
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })

    spend.outputs[1] = Ord.payOutputFor(PrivateKey.fromRandom(), PRICE) // thief's address
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(false)
  })

  it('pays a distinct payTo recipient while the seller keeps cancel rights', function () {
    const payee = PrivateKey.fromRandom()
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), payTo: payee.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(payee, PRICE))
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('purchase() fail-fasts (throws) when the payout output is wrong', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE - 1)) // underpay
    const pinned = Ord.payOutputFor(seller, PRICE)
    ;(function () {
      Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS, payOutput: pinned })
    }).should.throw(/would not be paid/)
  })

  it('lets the seller CANCEL the listing with their key', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(seller, ORD_SATS)) // seller reclaims the ordinal
    Ord.cancelOrdLock({ privateKey: seller, spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('rejects a CANCEL signed by the wrong key', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    Ord.cancelOrdLock({ privateKey: buyer, spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(false)
  })

  it('listInscriptionOutput is a 1-sat output whose script cancels + purchases', function () {
    const out = Ord.listInscriptionOutput({ seller: seller.toAddress(), price: PRICE })
    out.satoshis.should.equal(1)
    // Purchase path round-trips through the interpreter.
    const lock = out.script
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE))
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('can inscribe + list in one output; the envelope is inert and parseable', function () {
    const lock = Ord.buildOrdLock({
      seller: seller.toAddress(),
      price: PRICE,
      inscription: { contentType: 'text/plain', content: 'for sale' }
    })
    // The inscription rides along and is recoverable.
    Ord.isInscription(lock).should.equal(true)
    Ord.parseInscription(lock).contentText.should.equal('for sale')
    // ...and the covenant still enforces payment.
    const spend = fundListing(lock)
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE))
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })
})

describe('Ordinals OrdLock — multi-output payments (royalties + marketplace fee)', function () {
  this.timeout(20000)
  const I = bsv.Script.Interpreter
  let saved
  before(function () {
    saved = I.getLimits()
    SC.enableGenesis()
  })
  after(function () {
    I.setLimits(saved)
  })

  const seller = PrivateKey.fromRandom()
  const royalty = PrivateKey.fromRandom()
  const market = PrivateKey.fromRandom()
  const buyer = PrivateKey.fromRandom()
  const ROY = 5000
  const FEE = 2000

  function multiLock () {
    return Ord.buildOrdLock({
      seller: seller.toAddress(),
      price: PRICE,
      royalties: [{ address: royalty.toAddress(), satoshis: ROY }, { address: market.toAddress(), satoshis: FEE }]
    })
  }

  // The three pinned outputs, in order, that a purchase must recreate.
  function pinnedOuts () {
    return [Ord.payOutputFor(seller, PRICE), Ord.payOutputFor(royalty, ROY), Ord.payOutputFor(market, FEE)]
  }

  it('pays seller + royalty + marketplace fee atomically (auto-derived payoutCount)', function () {
    const lock = multiLock()
    const spend = help.fundAndSpend(lock, ORD_SATS, {}).spend
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS)) // ordinal -> buyer
    pinnedOuts().forEach(function (o) { spend.addOutput(o) }) // the 3 pinned payments
    spend.addOutput(p2pkhOutput(buyer, 10000)) // buyer change (trailing)
    // No payoutCount passed — purchaseOrdLock reads it from the listing script.
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('rejects a purchase that skips the royalty payment', function () {
    const lock = multiLock()
    const spend = help.fundAndSpend(lock, ORD_SATS, {}).spend
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    pinnedOuts().forEach(function (o) { spend.addOutput(o) })
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS, validate: false })
    // Zero out the royalty (output index 2) after signing → covenant must reject.
    spend.outputs[2] = Ord.payOutputFor(royalty, 1)
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(false)
  })

  it('rejects a purchase that redirects the marketplace fee', function () {
    const lock = multiLock()
    const spend = help.fundAndSpend(lock, ORD_SATS, {}).spend
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    pinnedOuts().forEach(function (o) { spend.addOutput(o) })
    Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS, validate: false })
    spend.outputs[3] = Ord.payOutputFor(PrivateKey.fromRandom(), FEE) // thief keeps the fee
    verify(spend.inputs[0].script, lock, { tx: spend, satoshis: ORD_SATS }).ok.should.equal(false)
  })

  it('purchaseOrdLock fail-fasts if a pinned payment is missing before broadcast', function () {
    const lock = multiLock()
    const spend = help.fundAndSpend(lock, ORD_SATS, {}).spend
    spend.addOutput(p2pkhOutput(buyer, ORD_SATS))
    spend.addOutput(Ord.payOutputFor(seller, PRICE))
    spend.addOutput(Ord.payOutputFor(royalty, ROY))
    spend.addOutput(Ord.payOutputFor(market, 1)) // underpays the fee
    ;(function () {
      Ord.purchaseOrdLock({ spend, lockingScript: lock, satoshis: ORD_SATS })
    }).should.throw(/would not be paid/)
  })
})

describe('Ordinals OrdLock — parseOrdLock (self-describing listings)', function () {
  const seller = PrivateKey.fromRandom()
  const royalty = PrivateKey.fromRandom()

  it('recovers seller, payments, total price, and inscription', function () {
    const lock = Ord.buildOrdLock({
      seller: seller.toAddress(),
      price: PRICE,
      royalties: [{ address: royalty.toAddress(), satoshis: 7500 }],
      inscription: { contentType: 'image/png', content: 'PNGDATA' }
    })
    const p = Ord.parseOrdLock(lock)
    p.should.be.an('object')
    p.seller.address.should.equal(seller.toAddress().toString())
    p.payOutputs.length.should.equal(2)
    p.payOutputs[0].satoshis.should.equal(PRICE)
    p.payOutputs[0].address.should.equal(seller.toAddress().toString())
    p.payOutputs[1].satoshis.should.equal(7500)
    p.payOutputs[1].address.should.equal(royalty.toAddress().toString())
    p.totalPrice.should.equal(PRICE + 7500)
    p.inscription.contentType.should.equal('image/png')
    p.inscription.contentText.should.equal('PNGDATA')
  })

  it('isOrdLock distinguishes a listing from a plain P2PKH and an inscription', function () {
    const lock = Ord.buildOrdLock({ seller: seller.toAddress(), price: PRICE })
    Ord.isOrdLock(lock).should.equal(true)
    Ord.isOrdLock(lock.toHex()).should.equal(true) // accepts hex too
    Ord.isOrdLock(bsv.Script.buildPublicKeyHashOut(seller.toAddress())).should.equal(false)
    Ord.isOrdLock(Ord.buildInscription({ address: seller.toAddress(), content: 'x' })).should.equal(false)
  })

  it('parseOrdLock returns null for a non-listing script', function () {
    const isNull = Ord.parseOrdLock(bsv.Script.buildPublicKeyHashOut(seller.toAddress())) === null
    isNull.should.equal(true)
  })
})

describe('Ordinals OrdLock — buildPurchaseTx (end-to-end)', function () {
  this.timeout(20000)
  const I = bsv.Script.Interpreter
  let saved
  before(function () {
    saved = I.getLimits()
    SC.enableGenesis()
  })
  after(function () {
    I.setLimits(saved)
  })

  const seller = PrivateKey.fromRandom()
  const royalty = PrivateKey.fromRandom()
  const buyer = PrivateKey.fromRandom()
  const fundKey = PrivateKey.fromRandom()
  const fundScript = bsv.Script.buildPublicKeyHashOut(fundKey.toAddress())

  function listing () {
    const lock = Ord.buildOrdLock({
      seller: seller.toAddress(),
      price: PRICE,
      royalties: [{ address: royalty.toAddress(), satoshis: 5000 }]
    })
    return { txid: 'a1'.repeat(32), outputIndex: 0, script: lock, satoshis: ORD_SATS }
  }

  function fundingCoins (amounts) {
    return amounts.map(function (sats, i) {
      return { txid: 'f' + i + '0'.repeat(62), outputIndex: i, script: fundScript, satoshis: sats, privateKey: fundKey }
    })
  }

  // Verify every input of a built tx through the consensus interpreter.
  function verifyAllInputs (tx, l, funding) {
    const r0 = verify(tx.inputs[0].script, l.script, { tx, satoshis: l.satoshis, inputIndex: 0 })
    r0.ok.should.equal(true)
    funding.forEach(function (f, i) {
      const r = verify(tx.inputs[i + 1].script, fundScript, { tx, satoshis: f.satoshis, inputIndex: i + 1 })
      r.ok.should.equal(true)
    })
  }

  it('assembles a fully-signed purchase from just the listing UTXO and buyer coins', function () {
    const l = listing()
    const funding = fundingCoins([80000, 60000])
    const tx = Ord.buildPurchaseTx({
      listing: l, ordinalDestination: buyer.toAddress(), funding, fee: 500
    })
    // Layout: [ordinal->buyer, seller PRICE, royalty 5000, change].
    tx.inputs.length.should.equal(3)
    tx.outputs.length.should.equal(4)
    tx.outputs[0].satoshis.should.equal(ORD_SATS)
    tx.outputs[1].satoshis.should.equal(PRICE)
    tx.outputs[2].satoshis.should.equal(5000)
    // Value conservation: in 1+80000+60000 = 140001; out 1+100000+5000+change; fee 500.
    tx.outputs[3].satoshis.should.equal(140001 - ORD_SATS - PRICE - 5000 - 500)
    verifyAllInputs(tx, l, funding)
  })

  it('reads the required payments straight off the listing (buyer supplies no terms)', function () {
    const l = listing()
    const funding = fundingCoins([200000])
    const tx = Ord.buildPurchaseTx({ listing: l, ordinalDestination: buyer.toAddress(), funding, fee: 250 })
    // The pinned payments came from parseOrdLock, and the covenant still validates.
    verifyAllInputs(tx, l, funding)
    tx.outputs[1].satoshis.should.equal(PRICE) // seller
    tx.outputs[2].satoshis.should.equal(5000) // royalty
  })

  it('omits the change output when funding is exact', function () {
    const l = listing()
    const funding = fundingCoins([PRICE + 5000 + 500]) // exactly payments + fee
    const tx = Ord.buildPurchaseTx({ listing: l, ordinalDestination: buyer.toAddress(), funding, fee: 500 })
    tx.outputs.length.should.equal(3) // ordinal + 2 payments, no change
    verifyAllInputs(tx, l, funding)
  })

  it('throws on insufficient funding', function () {
    const l = listing()
    const funding = fundingCoins([1000]) // nowhere near PRICE + royalty + fee
    ;(function () {
      Ord.buildPurchaseTx({ listing: l, ordinalDestination: buyer.toAddress(), funding, fee: 500 })
    }).should.throw(/insufficient funding/)
  })

  it('the covenant still binds — tampering any output after build breaks input 0', function () {
    const l = listing()
    const funding = fundingCoins([200000])
    const tx = Ord.buildPurchaseTx({ listing: l, ordinalDestination: buyer.toAddress(), funding, fee: 500 })
    tx.outputs[1] = Ord.payOutputFor(PrivateKey.fromRandom(), PRICE) // steal the seller payment
    verify(tx.inputs[0].script, l.script, { tx, satoshis: l.satoshis, inputIndex: 0 }).ok.should.equal(false)
  })
})

describe('Ordinals OrdLock — full lifecycle (list -> buy / cancel)', function () {
  this.timeout(20000)
  const I = bsv.Script.Interpreter
  let saved
  before(function () {
    saved = I.getLimits()
    SC.enableGenesis()
  })
  after(function () {
    I.setLimits(saved)
  })

  const owner = PrivateKey.fromRandom() // current ordinal owner / seller
  const royalty = PrivateKey.fromRandom()
  const buyer = PrivateKey.fromRandom()
  const fundKey = PrivateKey.fromRandom()
  const fundScript = bsv.Script.buildPublicKeyHashOut(fundKey.toAddress())
  const ownerScript = bsv.Script.buildPublicKeyHashOut(owner.toAddress())

  // The ordinal UTXO currently held by the owner under P2PKH.
  function ordinalUtxo () {
    return { txid: '0e'.repeat(32), outputIndex: 0, script: ownerScript, satoshis: ORD_SATS, privateKey: owner }
  }
  function fundCoin (sats, i) {
    return { txid: 'f' + (i || 0) + '0'.repeat(62), outputIndex: 0, script: fundScript, satoshis: sats, privateKey: fundKey }
  }

  it('buildListingTx signs the ordinal + fee and preserves the sat into the listing', function () {
    const funding = [fundCoin(20000)]
    const out = Ord.buildListingTx({
      ordinal: ordinalUtxo(),
      seller: owner.toAddress(),
      price: PRICE,
      royalties: [{ address: royalty.toAddress(), satoshis: 4000 }],
      funding,
      fee: 500
    })
    // Output 0 is the listing (ordinal's sat), and it's a parseable OrdLock.
    out.tx.outputs[0].satoshis.should.equal(ORD_SATS)
    out.listingOutpoint.outputIndex.should.equal(0)
    Ord.isOrdLock(out.tx.outputs[0].script).should.equal(true)
    Ord.parseOrdLock(out.listingScript).totalPrice.should.equal(PRICE + 4000)
    // Change = funding - fee.
    out.tx.outputs[1].satoshis.should.equal(20000 - 500)
    // Both inputs (ordinal P2PKH + funding P2PKH) verify.
    verify(out.tx.inputs[0].script, ownerScript, { tx: out.tx, satoshis: ORD_SATS, inputIndex: 0 }).ok.should.equal(true)
    verify(out.tx.inputs[1].script, fundScript, { tx: out.tx, satoshis: 20000, inputIndex: 1 }).ok.should.equal(true)
  })

  it('a listing created by buildListingTx can then be PURCHASED end-to-end', function () {
    // 1) Seller lists.
    const listed = Ord.buildListingTx({
      ordinal: ordinalUtxo(),
      seller: owner.toAddress(),
      price: PRICE,
      royalties: [{ address: royalty.toAddress(), satoshis: 4000 }],
      funding: [fundCoin(20000)],
      fee: 500
    })
    // 2) Buyer purchases the freshly-created listing UTXO (terms read off its script).
    const listing = {
      txid: listed.listingOutpoint.txid,
      outputIndex: listed.listingOutpoint.outputIndex,
      script: listed.listingScript,
      satoshis: ORD_SATS
    }
    const buyFunding = [fundCoin(200000, 1)]
    const buyTx = Ord.buildPurchaseTx({
      listing, ordinalDestination: buyer.toAddress(), funding: buyFunding, fee: 500
    })
    // Ordinal -> buyer, seller + royalty paid, change back to buyer.
    buyTx.outputs[0].satoshis.should.equal(ORD_SATS)
    buyTx.outputs[1].satoshis.should.equal(PRICE)
    buyTx.outputs[2].satoshis.should.equal(4000)
    // Covenant input + funding input both verify through the interpreter.
    verify(buyTx.inputs[0].script, listing.script, { tx: buyTx, satoshis: ORD_SATS, inputIndex: 0 }).ok.should.equal(true)
    verify(buyTx.inputs[1].script, fundScript, { tx: buyTx, satoshis: 200000, inputIndex: 1 }).ok.should.equal(true)
  })

  it('a listing created by buildListingTx can instead be CANCELLED by the seller', function () {
    const listed = Ord.buildListingTx({
      ordinal: ordinalUtxo(),
      seller: owner.toAddress(),
      price: PRICE,
      funding: [fundCoin(20000)],
      fee: 500
    })
    // Seller reclaims the ordinal from the listing UTXO.
    const reclaim = new Transaction()
    reclaim.addInput(new Transaction.Input({
      prevTxId: listed.listingOutpoint.txid, outputIndex: 0, script: Script.empty()
    }), listed.listingScript, ORD_SATS)
    reclaim.addOutput(p2pkhOutput(owner, ORD_SATS))
    Ord.cancelOrdLock({ privateKey: owner, spend: reclaim, lockingScript: listed.listingScript, satoshis: ORD_SATS })
    verify(reclaim.inputs[0].script, listed.listingScript, { tx: reclaim, satoshis: ORD_SATS }).ok.should.equal(true)
  })

  it('buildListingTx throws when funding cannot cover the fee', function () {
    ;(function () {
      Ord.buildListingTx({
        ordinal: ordinalUtxo(),
        seller: owner.toAddress(),
        price: PRICE,
        funding: [fundCoin(300)],
        fee: 500
      })
    }).should.throw(/insufficient funding/)
  })
})

describe('Ordinals OrdLock — code-review regressions', function () {
  this.timeout(20000)
  const I = bsv.Script.Interpreter
  let saved
  before(function () {
    saved = I.getLimits()
    SC.enableGenesis()
  })
  after(function () {
    I.setLimits(saved)
  })

  const owner = PrivateKey.fromRandom()
  const fundKey = PrivateKey.fromRandom()
  const ownerScript = bsv.Script.buildPublicKeyHashOut(owner.toAddress())
  const fundScript = bsv.Script.buildPublicKeyHashOut(fundKey.toAddress())

  // Finding #1: buildListingTx must sign the ordinal input with the resolved value even
  // when the caller omits ordinal.satoshis (documented to default to 1).
  it('buildListingTx signs a valid ordinal input when ordinal.satoshis is omitted', function () {
    const out = Ord.buildListingTx({
      ordinal: { txid: '0e'.repeat(32), outputIndex: 0, script: ownerScript, privateKey: owner }, // no satoshis
      seller: owner.toAddress(),
      price: PRICE,
      funding: [{ txid: 'f0'.repeat(32), outputIndex: 0, script: fundScript, satoshis: 20000, privateKey: fundKey }],
      fee: 500
    })
    verify(out.tx.inputs[0].script, ownerScript, { tx: out.tx, satoshis: 1, inputIndex: 0 }).ok.should.equal(true)
  })

  // Finding #2: parsed addresses honor a network option instead of always being livenet.
  it('parseOrdLock formats addresses for the requested network', function () {
    const lock = Ord.buildOrdLock({ seller: owner.toAddress(), price: PRICE })
    const live = Ord.parseOrdLock(lock).seller.address
    const test = Ord.parseOrdLock(lock, { network: 'testnet' }).seller.address
    live.should.not.equal(test)
    bsv.Address.fromString(test).network.name.should.equal('testnet')
    bsv.Address.fromString(live).network.name.should.equal('livenet')
  })

  // Finding #3: a funding coin missing satoshis fails fast (was a silent wrong-amount signature).
  it('buildPurchaseTx throws when a funding coin has no satoshis', function () {
    const lock = Ord.buildOrdLock({ seller: owner.toAddress(), price: PRICE })
    ;(function () {
      Ord.buildPurchaseTx({
        listing: { txid: 'a1'.repeat(32), outputIndex: 0, script: lock, satoshis: 1 },
        ordinalDestination: fundKey.toAddress(),
        funding: [{ txid: 'b1'.repeat(32), outputIndex: 0, script: fundScript, privateKey: fundKey }], // no satoshis
        fee: 500
      })
    }).should.throw(/satoshis/)
  })

  // Finding #5: payOutputFor never silently ignores price when handed a full Output.
  it('payOutputFor rejects a Transaction.Output (price would be ignored)', function () {
    const o = new bsv.Transaction.Output({ script: ownerScript, satoshis: 5 })
    ;(function () { Ord.payOutputFor(o, PRICE) }).should.throw()
  })

  it('buildOrdLock still accepts a pre-built Output as payTo (uses its own value)', function () {
    const lock = Ord.buildOrdLock({
      seller: owner.toAddress(),
      price: 1,
      payTo: new bsv.Transaction.Output({ script: ownerScript, satoshis: 777 })
    })
    Ord.parseOrdLock(lock).totalPrice.should.equal(777)
  })

  // parseOrdLock recovers terms from the script's shape. Shape alone proves nothing: a
  // script wearing the same opcode arrangement without the OP_PUSH_TX covenant enforces no
  // payment, and reporting a seller and a price for it invents a listing that does not
  // exist. The terms are therefore verified by rebuilding the listing and comparing bytes.
  describe('is a verifier, not a shape matcher', function () {
    const attacker = bsv.PrivateKey.fromBuffer(Buffer.alloc(32, 9))

    // Wears the fingerprint parseOrdLock keys off: a top-level OP_IF with a 20-byte push,
    // and OP_TOALTSTACK <blob> OP_CAT OP_SWAP in the OP_ELSE branch. Enforces nothing.
    function fabricatedListing () {
      const payout = new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(attacker.toAddress()),
        satoshis: 100000000
      })
      const s = new bsv.Script()
      s.add(bsv.Opcode.OP_IF)
      s.add(attacker.toAddress().hashBuffer)
      s.add(bsv.Opcode.OP_DROP)
      s.add(bsv.Opcode.OP_ELSE)
      s.add(bsv.Opcode.OP_TOALTSTACK)
      s.add(payout.toBufferWriter().toBuffer())
      s.add(bsv.Opcode.OP_CAT)
      s.add(bsv.Opcode.OP_SWAP)
      s.add(bsv.Opcode.OP_ENDIF)
      s.add(bsv.Opcode.OP_TRUE)
      return s
    }

    it('rejects a fabricated listing that enforces no payment', function () {
      const fake = fabricatedListing()
      Ord.isOrdLock(fake).should.equal(false)
      ;(Ord.parseOrdLock(fake) === null).should.equal(true)
    })

    it('proves the fabricated listing really is spendable for free', function () {
      // Without this, the test above only shows we reject *something*.
      const interp = new bsv.Script.Interpreter()
      const unlock = new bsv.Script().add(bsv.Opcode.OP_1)
      const spent = interp.verify(unlock, fabricatedListing(), new bsv.Transaction(), 0, 0)
      spent.should.equal(true)
    })

    it('rejects a genuine listing with anything appended', function () {
      const real = Ord.buildOrdLock({ seller: owner.toAddress(), price: 50000 })
      const tampered = bsv.Script.fromHex(real.toHex()).add(bsv.Opcode.OP_NOP)
      Ord.isOrdLock(tampered).should.equal(false)
    })

    it('still accepts every genuine listing shape', function () {
      const simple = Ord.buildOrdLock({ seller: owner.toAddress(), price: 50000 })
      Ord.parseOrdLock(simple).totalPrice.should.equal(50000)

      const withInsc = Ord.buildOrdLock({
        seller: owner.toAddress(),
        price: 777,
        inscription: { contentType: 'text/plain', content: 'for sale' }
      })
      const parsed = Ord.parseOrdLock(withInsc)
      parsed.totalPrice.should.equal(777)
      parsed.inscription.contentText.should.equal('for sale')

      const multi = Ord.buildOrdLock({
        seller: owner.toAddress(),
        price: 1000,
        royalties: [{ address: attacker.toAddress(), satoshis: 50 }]
      })
      Ord.parseOrdLock(multi).payOutputs.length.should.equal(2)
      Ord.parseOrdLock(multi).totalPrice.should.equal(1050)
    })
  })
})
