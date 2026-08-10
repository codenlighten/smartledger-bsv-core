'use strict'

import _ = require('../../util/_')
import inherits = require('inherits')
import Input = require('./input')
import OutputImpl = require('../output')
const $ = require('../../util/preconditions')

import type { Script, ScriptConstructor } from '../../script/script.types'
import type { MultiSigScriptHashInput as MSInput, MultiSigInputConstructor } from '../types'
import type { Output as OutputType } from '../types'

// script and publickey are in this cycle, so both resolve on demand.
const scriptClass = (): ScriptConstructor => require('../../script')
const publicKeyClass = (): any => require('../../publickey')
import Signature = require('../../crypto/signature')
import Sighash = require('../sighash')
import TransactionSignature = require('../signature')
import Varint = require('../../encoding/varint')
import type { Transaction, TransactionSignatureObj } from '../types'
import type { PrivateKey } from '../../privatekey.types'
import type { PublicKey } from '../../publickey.types'
import type { BufferReader, BufferWriter } from '../../encoding/types'

/**
 * @constructor
 */
const MultiSigScriptHashInput = function MultiSigScriptHashInput (this: MSInput, input: Record<string, unknown>, pubkeys?: unknown[], threshold?: number, signatures?: unknown[]) {
  Input.apply(this, arguments as unknown as [])
  const self = this
  const keys = (pubkeys ?? input.publicKeys) as unknown[]
  const thr = (threshold ?? input.threshold) as number
  const sigs = (signatures ?? input.signatures) as unknown[] | undefined
  this.publicKeys = keys.map((k: any) => k.toString('hex')).sort().map((k: string) => new (publicKeyClass())(k))
  this.redeemScript = scriptClass().buildMultisigOut(this.publicKeys, thr)
  $.checkState(scriptClass().buildScriptHashOut(this.redeemScript).equals((this.output as OutputType).script),
    'Provided public keys don\'t hash to the provided output')
  this.publicKeyIndex = {}
  _.each(this.publicKeys, function (publicKey: PublicKey, index: number) {
    self.publicKeyIndex[publicKey.toString()] = index
  })
  this.threshold = thr
  // Empty array of signatures
  this.signatures = sigs != null ? this._deserializeSignatures(sigs as Array<TransactionSignatureObj | TransactionSignature>) : new Array(this.publicKeys.length)
} as unknown as MultiSigInputConstructor
inherits(MultiSigScriptHashInput, Input)

MultiSigScriptHashInput.prototype.toObject = function (this: MSInput): Record<string, unknown> {
  const obj = Input.prototype.toObject.apply(this, arguments as unknown as []) as Record<string, unknown>
  obj.threshold = this.threshold
  obj.publicKeys = _.map(this.publicKeys, function (publicKey) { return publicKey.toString() })
  obj.signatures = this._serializeSignatures()
  return obj
}

MultiSigScriptHashInput.prototype._deserializeSignatures = function (this: MSInput, signatures: Array<TransactionSignatureObj | TransactionSignature | undefined>): Array<TransactionSignature | undefined> {
  // Sparse by design: an empty slot means "no signature for publicKeys[i]",
  // so the falsy check must stay — the array is pre-sized with holes.
  return _.map(signatures, function (signature?: TransactionSignatureObj | TransactionSignature) {
    if (!signature) {
      return undefined
    }
    return new TransactionSignature(signature)
  })
}

MultiSigScriptHashInput.prototype._serializeSignatures = function (this: MSInput): Array<TransactionSignatureObj | undefined> {
  return _.map(this.signatures, function (signature?: TransactionSignature) {
    if (!signature) {
      return undefined
    }
    return signature.toObject()
  })
}

MultiSigScriptHashInput.prototype.getSignatures = function (this: MSInput, transaction: Transaction, privateKey: PrivateKey, index: number, sigtype?: number): unknown[] {
  $.checkState(this.output instanceof (OutputImpl as unknown as new () => unknown))
  sigtype = sigtype || (Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID)

  const self = this
  const results: unknown[] = []
  _.each(this.publicKeys, function (publicKey: PublicKey) {
    if (publicKey.toString() === privateKey.publicKey.toString()) {
      results.push(new TransactionSignature({
        publicKey: privateKey.publicKey,
        prevTxId: self.prevTxId,
        outputIndex: self.outputIndex,
        inputIndex: index,
        signature: Sighash.sign(transaction, privateKey, sigtype, index, self.redeemScript, (self.output as OutputType).satoshisBN),
        sigtype
      }))
    }
  })
  return results
}

MultiSigScriptHashInput.prototype.addSignature = function (this: MSInput, transaction: Transaction, signature: TransactionSignature): MSInput {
  $.checkState(!this.isFullySigned(), 'All needed signatures have already been added')
  $.checkArgument(!_.isUndefined(this.publicKeyIndex[signature.publicKey.toString()]),
    'Signature has no matching public key')
  $.checkState(this.isValidSignature(transaction, signature))
  // Checked non-undefined by the checkArgument above.
  this.signatures[this.publicKeyIndex[signature.publicKey.toString()] as number] = signature
  this._updateScript()
  return this
}

MultiSigScriptHashInput.prototype._updateScript = function (this: MSInput): MSInput {
  this.setScript(scriptClass().buildP2SHMultisigIn(
    this.publicKeys,
    this.threshold,
    this._createSignatures(),
    { cachedMultisig: this.redeemScript }
  ))
  return this
}

MultiSigScriptHashInput.prototype._createSignatures = function (this: MSInput): Buffer[] {
  return _.map(
    _.filter(this.signatures, function (signature?: TransactionSignature) { return !_.isUndefined(signature) }) as TransactionSignature[],
    function (signature: TransactionSignature) {
      return Buffer.concat([
        signature.signature.toDER(),
        Buffer.from([signature.sigtype & 0xff])
      ])
    }
  )
}

MultiSigScriptHashInput.prototype.clearSignatures = function (this: MSInput): void {
  this.signatures = new Array(this.publicKeys.length)
  this._updateScript()
}

MultiSigScriptHashInput.prototype.isFullySigned = function (this: MSInput): boolean {
  return this.countSignatures() === this.threshold
}

MultiSigScriptHashInput.prototype.countMissingSignatures = function (this: MSInput): number {
  return this.threshold - this.countSignatures()
}

MultiSigScriptHashInput.prototype.countSignatures = function (this: MSInput): number {
  return _.reduce(this.signatures, function (sum: number, signature: unknown) {
    // The original relied on boolean-to-number coercion; made explicit.
    return sum + (signature != null ? 1 : 0)
  }, 0)
}

MultiSigScriptHashInput.prototype.publicKeysWithoutSignature = function (this: MSInput): any[] {
  const self = this
  return _.filter(this.publicKeys, function (publicKey: PublicKey) {
    const idx = self.publicKeyIndex[publicKey.toString()]
    return idx === undefined || self.signatures[idx] == null
  })
}

MultiSigScriptHashInput.prototype.isValidSignature = function (this: MSInput, transaction: Transaction, signature: TransactionSignature): boolean {
  // FIXME: Refactor signature so this is not necessary
  signature.signature.nhashtype = signature.sigtype
  return Sighash.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    this.redeemScript,
    (this.output as OutputType).satoshisBN
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

MultiSigScriptHashInput.prototype._estimateSize = function (this: MSInput): number {
  const pubKeysSize = this.publicKeys.length * (MultiSigScriptHashInput.PUBKEY_SIZE as number)
  const sigsSize = this.threshold * (MultiSigScriptHashInput.SIGNATURE_SIZE as number)
  const redeemScriptSize = 3 + pubKeysSize
  const redeemScriptPushdataSize = redeemScriptSize <= 75 ? 1 : redeemScriptSize <= 255 ? 2 : 3
  const scriptLength = sigsSize + 1 + redeemScriptPushdataSize + redeemScriptSize
  return Input.BASE_SIZE + Varint(scriptLength).toBuffer().length + scriptLength
}

export = MultiSigScriptHashInput
