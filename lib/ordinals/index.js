'use strict'
/**
 * Ordinals — 1Sat Ordinals inscriptions for BSV.
 *
 * Build/parse inscription scripts, create the 1-sat inscription output, batch many
 * inscriptions into one transaction, and (see ./ordlock) list an ordinal for sale
 * behind an OP_PUSH_TX "pay the seller or cancel" covenant.
 */
const inscription = require('./inscription')
const ordlock = require('./ordlock')
const bsv20 = require('./bsv20')

/**
 * Build the 1-sat output(s) for one or more inscriptions.
 * @param {Array<object>} items  each: { contentType, content, address|lock, satoshis? }
 * @returns {Transaction.Output[]}
 */
function batchInscriptionOutputs (items) {
  if (!Array.isArray(items) || !items.length) {
    throw new Error('batchInscriptionOutputs requires a non-empty array of items')
  }
  return items.map(function (it) { return inscription.createInscriptionOutput(it) })
}

module.exports = {
  buildInscription: inscription.buildInscription,
  parseInscription: inscription.parseInscription,
  isInscription: inscription.isInscription,
  createInscriptionOutput: inscription.createInscriptionOutput,
  batchInscriptionOutputs,

  // Marketplace: list an ordinal for sale behind a "pay the seller or cancel" covenant.
  // Payments may be multi-output (seller + royalties + marketplace fee), and a listing is
  // self-describing — parseOrdLock recovers its terms and buildPurchaseTx assembles a
  // complete signed purchase from just the listing UTXO and the buyer's coins.
  ORDLOCK_SIGHASH: ordlock.ORDLOCK_SIGHASH,
  buildOrdLock: ordlock.buildOrdLock,
  parseOrdLock: ordlock.parseOrdLock,
  isOrdLock: ordlock.isOrdLock,
  listInscriptionOutput: ordlock.listInscriptionOutput,
  payOutputFor: ordlock.payOutputFor,
  purchaseOrdLock: ordlock.purchase,
  cancelOrdLock: ordlock.cancel,
  buildListingTx: ordlock.buildListingTx,
  buildPurchaseTx: ordlock.buildPurchaseTx,

  // BSV-20 / BSV-21 fungible-token inscriptions (deploy / mint / transfer + parse).
  BSV20: bsv20
}
