'use strict'

const _ = require('../../util/_')
const inherits = require('inherits')
const Input = require('./input')
const Output = require('../output')
const $ = require('../../util/preconditions')

const Script = require('../../script')
const Signature = require('../../crypto/signature')
const Sighash = require('../sighash')
const TransactionSignature = require('../signature')
const PublicKey = require('../../publickey')
const Varint = require('../../encoding/varint')

/**
 * @constructor
 */
function MultiSigScriptHashInput (input, pubkeys, threshold, signatures) {
  Input.apply(this, arguments)
  const self = this
  pubkeys = pubkeys || input.publicKeys
  threshold = threshold || input.threshold
  signatures = signatures || input.signatures
  this.publicKeys = pubkeys.map(k => k.toString('hex')).sort().map(k => new PublicKey(k))
  this.redeemScript = Script.buildMultisigOut(this.publicKeys, threshold)
  $.checkState(Script.buildScriptHashOut(this.redeemScript).equals(this.output.script),
    'Provided public keys don\'t hash to the provided output')
  this.publicKeyIndex = {}
  _.each(this.publicKeys, function (publicKey, index) {
    self.publicKeyIndex[publicKey.toString()] = index
  })
  this.threshold = threshold
  // Empty array of signatures
  this.signatures = signatures ? this._deserializeSignatures(signatures) : new Array(this.publicKeys.length)
}
inherits(MultiSigScriptHashInput, Input)

MultiSigScriptHashInput.prototype.toObject = function () {
  const obj = Input.prototype.toObject.apply(this, arguments)
  obj.threshold = this.threshold
  obj.publicKeys = _.map(this.publicKeys, function (publicKey) { return publicKey.toString() })
  obj.signatures = this._serializeSignatures()
  return obj
}

MultiSigScriptHashInput.prototype._deserializeSignatures = function (signatures) {
  return _.map(signatures, function (signature) {
    if (!signature) {
      return undefined
    }
    return new TransactionSignature(signature)
  })
}

MultiSigScriptHashInput.prototype._serializeSignatures = function () {
  return _.map(this.signatures, function (signature) {
    if (!signature) {
      return undefined
    }
    return signature.toObject()
  })
}

MultiSigScriptHashInput.prototype.getSignatures = function (transaction, privateKey, index, sigtype) {
  $.checkState(this.output instanceof Output)
  sigtype = sigtype || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

  const self = this
  const results = []
  _.each(this.publicKeys, function (publicKey) {
    if (publicKey.toString() === privateKey.publicKey.toString()) {
      results.push(new TransactionSignature({
        publicKey: privateKey.publicKey,
        prevTxId: self.prevTxId,
        outputIndex: self.outputIndex,
        inputIndex: index,
        signature: Sighash.sign(transaction, privateKey, sigtype, index, self.redeemScript, self.output.satoshisBN),
        sigtype
      }))
    }
  })
  return results
}

MultiSigScriptHashInput.prototype.addSignature = function (transaction, signature) {
  $.checkState(!this.isFullySigned(), 'All needed signatures have already been added')
  $.checkArgument(!_.isUndefined(this.publicKeyIndex[signature.publicKey.toString()]),
    'Signature has no matching public key')
  $.checkState(this.isValidSignature(transaction, signature))
  this.signatures[this.publicKeyIndex[signature.publicKey.toString()]] = signature
  this._updateScript()
  return this
}

MultiSigScriptHashInput.prototype._updateScript = function () {
  this.setScript(Script.buildP2SHMultisigIn(
    this.publicKeys,
    this.threshold,
    this._createSignatures(),
    { cachedMultisig: this.redeemScript }
  ))
  return this
}

MultiSigScriptHashInput.prototype._createSignatures = function () {
  return _.map(
    _.filter(this.signatures, function (signature) { return !_.isUndefined(signature) }),
    function (signature) {
      return Buffer.concat([
        signature.signature.toDER(),
        Buffer.from([signature.sigtype & 0xff])
      ])
    }
  )
}

MultiSigScriptHashInput.prototype.clearSignatures = function () {
  this.signatures = new Array(this.publicKeys.length)
  this._updateScript()
}

MultiSigScriptHashInput.prototype.isFullySigned = function () {
  return this.countSignatures() === this.threshold
}

MultiSigScriptHashInput.prototype.countMissingSignatures = function () {
  return this.threshold - this.countSignatures()
}

MultiSigScriptHashInput.prototype.countSignatures = function () {
  return _.reduce(this.signatures, function (sum, signature) {
    return sum + (!!signature)
  }, 0)
}

MultiSigScriptHashInput.prototype.publicKeysWithoutSignature = function () {
  const self = this
  return _.filter(this.publicKeys, function (publicKey) {
    return !(self.signatures[self.publicKeyIndex[publicKey.toString()]])
  })
}

MultiSigScriptHashInput.prototype.isValidSignature = function (transaction, signature) {
  // FIXME: Refactor signature so this is not necessary
  signature.signature.nhashtype = signature.sigtype
  return Sighash.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    this.redeemScript,
    this.output.satoshisBN
  )
}

// 32   txid
// 4    output index
// --- script ---
// ???  script size (VARINT)
// 1    OP_0
// --- signature list ---
//      1       signature size (OP_PUSHDATA)
//      <=72    signature (DER + SIGHASH type)
//
// ???  redeem script size (OP_PUSHDATA)
// --- redeem script ---
//      1       OP_2
//      --- public key list ---
//      1       public key size (OP_PUSHDATA)
//      33      compressed public key
//
//      1       OP_3
//      1       OP_CHECKMULTISIG
//
// 4    sequence number
MultiSigScriptHashInput.SIGNATURE_SIZE = 73
MultiSigScriptHashInput.PUBKEY_SIZE = 34

MultiSigScriptHashInput.prototype._estimateSize = function () {
  const pubKeysSize = this.publicKeys.length * MultiSigScriptHashInput.PUBKEY_SIZE
  const sigsSize = this.threshold * MultiSigScriptHashInput.SIGNATURE_SIZE
  const redeemScriptSize = 3 + pubKeysSize
  const redeemScriptPushdataSize = redeemScriptSize <= 75 ? 1 : redeemScriptSize <= 255 ? 2 : 3
  const scriptLength = sigsSize + 1 + redeemScriptPushdataSize + redeemScriptSize
  return Input.BASE_SIZE + Varint(scriptLength).toBuffer().length + scriptLength
}

module.exports = MultiSigScriptHashInput
