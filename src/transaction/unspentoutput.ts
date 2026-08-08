'use strict'

import _ = require('../util/_')
import $ = require('../util/preconditions')
import JSUtil = require('../util/js')
import type { ScriptConstructor } from '../script/script.types'
import type { UnspentOutput, UnspentOutputData, UnspentOutputConstructor } from './types'

// Runtime edges into the cycle: resolved lazily at call time so nothing is
// dereferenced during module evaluation.
const scriptCtor = (): ScriptConstructor => require('../script')
const addressCtor = (): { fromString: (s: string) => unknown, fromObject: (o: unknown) => unknown } => require('../address')

/**
 * Represents an unspent output information: its script, associated amount and address,
 * transaction id and output index.
 *
 * @constructor
 * @param {object} data
 * @param {string} data.txid the previous transaction id
 * @param {string=} data.txId alias for `txid`
 * @param {number} data.vout the index in the transaction
 * @param {number=} data.outputIndex alias for `vout`
 * @param {string|Script} data.scriptPubKey the script that must be resolved to release the funds
 * @param {string|Script=} data.script alias for `scriptPubKey`
 * @param {number} data.amount amount of bitcoins associated
 * @param {number=} data.satoshis alias for `amount`, but expressed in satoshis (1 BSV = 1e8 satoshis)
 * @param {string|Address=} data.address the associated address to the script, if provided
 */
const UnspentOutput = function UnspentOutput (this: UnspentOutput, data: UnspentOutputData) {
  if (!(this instanceof UnspentOutput)) {
    return new (UnspentOutput as UnspentOutputConstructor)(data)
  }
  $.checkArgument(_.isObject(data), 'Must provide an object from where to extract data')
  const address = data.address != null ? new (addressCtor() as unknown as new (a: unknown) => unknown)(data.address) : undefined
  const txId = data.txid ? data.txid : data.txId
  if (!txId || !JSUtil.isHexaString(txId) || txId.length > 64) {
    // TODO: Use the errors library
    // NOTE: Error's second argument is `options`, not extra data — this has
            // never attached `data` to the error. Preserved as-is; changing it
            // would alter what callers see.
    throw new Error('Invalid TXID in object')
  }
  const outputIndex = _.isUndefined(data.vout) ? data.outputIndex : data.vout
  if (!_.isNumber(outputIndex)) {
    throw new Error('Invalid outputIndex, received ' + outputIndex)
  }
  $.checkArgument(!_.isUndefined(data.scriptPubKey) || !_.isUndefined(data.script),
    'Must provide the scriptPubKey for that output!')
  const script = new (scriptCtor())(data.scriptPubKey ?? data.script)
  $.checkArgument(!_.isUndefined(data.amount) || !_.isUndefined(data.satoshis),
    'Must provide an amount for the output')
  const amount = !_.isUndefined(data.amount) ? Math.round((data.amount as number) * 1e8) : data.satoshis
  $.checkArgument(_.isNumber(amount), 'Amount must be a number')
  JSUtil.defineImmutable(this, {
    address,
    txId,
    outputIndex,
    script,
    satoshis: amount
  })
} as unknown as UnspentOutputConstructor

/**
 * Provide an informative output when displaying this object in the console
 * @returns string
 */
UnspentOutput.prototype.inspect = function (this: UnspentOutput): string {
  return '<UnspentOutput: ' + this.txId + ':' + this.outputIndex +
         ', satoshis: ' + this.satoshis + ', address: ' + this.address + '>'
}

/**
 * String representation: just "txid:index"
 * @returns string
 */
UnspentOutput.prototype.toString = function (this: UnspentOutput): string {
  return this.txId + ':' + this.outputIndex
}

/**
 * Deserialize an UnspentOutput from an object
 * @param {object|string} data
 * @return UnspentOutput
 */
UnspentOutput.fromObject = function (data: UnspentOutputData): UnspentOutput {
  return new (UnspentOutput as UnspentOutputConstructor)(data)
}

/**
 * Returns a plain object (no prototype or methods) with the associated info for this output
 * @return {object}
 */
UnspentOutput.prototype.toObject = UnspentOutput.prototype.toJSON = function toObject (this: UnspentOutput): Record<string, unknown> {
  return {
    address: this.address ? this.address.toString() : undefined,
    txid: this.txId,
    vout: this.outputIndex,
    scriptPubKey: this.script.toBuffer().toString('hex'),
    amount: Number.parseFloat((this.satoshis / 1e8).toFixed(8))
  }
}

export = UnspentOutput
