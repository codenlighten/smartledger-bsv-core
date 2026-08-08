'use strict'

import _ = require('../../util/_')
import $ = require('../../util/preconditions')
import errors = require('../../errors')
import BufferWriter = require('../../encoding/bufferwriter')
import JSUtil = require('../../util/js')
import Sighash = require('../sighash')
import type { Input, InputConstructor, Output } from '../types'

// The error tree is built dynamically, so its members come through an index
// signature; narrow once here rather than at each throw.
type ErrCtor = new (...args: unknown[]) => Error
const abstractMethod = (): ErrCtor => errors.AbstractMethodInvoked as ErrCtor
import OutputImpl = require('../output')
import type { ScriptConstructor } from '../../script/script.types'

// script is in this cycle, so it is resolved on demand.
const scriptClass = (): ScriptConstructor => require('../../script')

const MAXINT = 0xffffffff // Math.pow(2, 32) - 1;
const DEFAULT_RBF_SEQNUMBER = MAXINT - 2
const DEFAULT_SEQNUMBER = MAXINT
const DEFAULT_LOCKTIME_SEQNUMBER = MAXINT - 1

const Input = function Input (this: Input, params?: Record<string, unknown>) {
  if (!(this instanceof Input)) {
    return new (Input as InputConstructor)(params)
  }
  if (params != null) {
    return this._fromObject(params)
  }
} as unknown as InputConstructor

Input.MAXINT = MAXINT
Input.DEFAULT_SEQNUMBER = DEFAULT_SEQNUMBER
Input.DEFAULT_LOCKTIME_SEQNUMBER = DEFAULT_LOCKTIME_SEQNUMBER
Input.DEFAULT_RBF_SEQNUMBER = DEFAULT_RBF_SEQNUMBER
// txid + output index + sequence number
Input.BASE_SIZE = 32 + 4 + 4

Object.defineProperty(Input.prototype, 'script', {
  configurable: false,
  enumerable: true,
  get: function (this: Input) {
    if (this.isNull()) {
      return null
    }
    if (this._script == null) {
      const s = new (scriptClass())(this._scriptBuffer)
      s._isInput = true
      this._script = s
    }
    return this._script
  }
})

Input.fromObject = function (obj: Record<string, unknown>): Input {
  $.checkArgument(_.isObject(obj))
  const input = new Input()
  return input._fromObject(obj)
}

Input.prototype._fromObject = function (this: Input, params: Record<string, unknown>): Input {
  let prevTxId: unknown
  if (_.isString(params.prevTxId) && JSUtil.isHexa(params.prevTxId)) {
    prevTxId = Buffer.from(params.prevTxId, 'hex')
  } else {
    prevTxId = params.prevTxId
  }
  this.output = params.output != null
    ? (params.output instanceof (OutputImpl as unknown as new () => unknown)
        ? params.output as Output
        : new OutputImpl(params.output as { satoshis?: unknown, script?: unknown }))
    : undefined
  // `||` and the txidbuf/txoutnum/seqnum aliases are the legacy field names;
  // kept as falsy checks because 0 is not a meaningful prevTxId here.
  this.prevTxId = (prevTxId ?? params.txidbuf) as Buffer
  this.outputIndex = (_.isUndefined(params.outputIndex) ? params.txoutnum : params.outputIndex) as number
  this.sequenceNumber = (_.isUndefined(params.sequenceNumber)
    ? (_.isUndefined(params.seqnum) ? DEFAULT_SEQNUMBER : params.seqnum)
    : params.sequenceNumber) as number
  if (_.isUndefined(params.script) && _.isUndefined(params.scriptBuffer)) {
    throw new (((errors.Transaction as Record<string, unknown>).Input as Record<string, unknown>).MissingScript as new () => Error)()
  }
  this.setScript(params.scriptBuffer ?? params.script)
  return this
}

Input.prototype.toObject = Input.prototype.toJSON = function toObject (this: Input): Record<string, unknown> {
  // Optional keys are added conditionally, so this stays an incrementally
  // built record rather than a literal.
  const obj: Record<string, unknown> = {
    prevTxId: this.prevTxId.toString('hex'),
    outputIndex: this.outputIndex,
    sequenceNumber: this.sequenceNumber,
    script: (this._scriptBuffer as Buffer).toString('hex')
  }
  // add human readable form if input contains valid script
  if (this.script != null) {
    obj.scriptString = this.script.toString()
  }
  if (this.output != null) {
    obj.output = this.output.toObject()
  }
  return obj
}

Input.fromBufferReader = function (br: any): Input {
  const input = new Input()
  input.prevTxId = br.readReverse(32)
  input.outputIndex = br.readUInt32LE()
  input._scriptBuffer = br.readVarLengthBuffer()
  input.sequenceNumber = br.readUInt32LE()
  // TODO: return different classes according to which input it is
  // e.g: CoinbaseInput, PublicKeyHashInput, MultiSigScriptHashInput, etc.
  return input
}

Input.prototype.toBufferWriter = function (this: Input, writer?: any): any {
  if (writer == null) {
    writer = new BufferWriter()
  }
  writer.writeReverse(this.prevTxId)
  writer.writeUInt32LE(this.outputIndex)
  const script = this._scriptBuffer as Buffer
  writer.writeVarintNum(script.length)
  writer.write(script)
  writer.writeUInt32LE(this.sequenceNumber)
  return writer
}

Input.prototype.setScript = function (this: Input, script: unknown): Input {
  const Script = scriptClass()
  this._script = null
  if (script instanceof (Script as unknown as new () => unknown)) {
    const sc = script as import('../../script/script.types').Script
    sc._isInput = true
    this._script = sc
    this._scriptBuffer = sc.toBuffer()
  } else if (script === null) {
    const sc = Script.empty()
    sc._isInput = true
    this._script = sc
    this._scriptBuffer = sc.toBuffer()
  } else if (JSUtil.isHexa(script)) {
    // hex string script
    this._scriptBuffer = Buffer.from(script as string, 'hex')
  } else if (_.isString(script)) {
    // human readable string script
    const sc = new Script(script)
    sc._isInput = true
    this._script = sc
    this._scriptBuffer = sc.toBuffer()
  } else if (Buffer.isBuffer(script)) {
    // buffer script
    this._scriptBuffer = Buffer.from(script)
  } else {
    throw new TypeError('Invalid argument type: script')
  }
  return this
}

/**
 * Retrieve signatures for the provided PrivateKey.
 *
 * @param {Transaction} transaction - the transaction to be signed
 * @param {PrivateKey} privateKey - the private key to use when signing
 * @param {number} inputIndex - the index of this input in the provided transaction
 * @param {number} sigType - defaults to Signature.SIGHASH_ALL
 * @param {Buffer} addressHash - if provided, don't calculate the hash of the
 *     public key associated with the private key provided
 * @abstract
 */
Input.prototype.getSignatures = function (this: Input): unknown[] {
  throw new (abstractMethod())(
    'Trying to sign unsupported output type (only P2PKH and P2SH multisig inputs are supported)' +
    ' for input: ' + JSON.stringify(this)
  )
}

Input.prototype.isFullySigned = function (this: Input): boolean {
  throw new (abstractMethod())('Input#isFullySigned')
}

Input.prototype.isFinal = function (this: Input): boolean {
  return this.sequenceNumber === Input.MAXINT
}

Input.prototype.addSignature = function (this: Input): Input {
  throw new (abstractMethod())('Input#addSignature')
}

Input.prototype.clearSignatures = function (this: Input): Input {
  throw new (abstractMethod())('Input#clearSignatures')
}

Input.prototype.isValidSignature = function (this: Input, transaction: any, signature: any): boolean {
  // FIXME: Refactor signature so this is not necessary
  signature.signature.nhashtype = signature.sigtype
  return Sighash.verify(
    transaction,
    signature.signature,
    signature.publicKey,
    signature.inputIndex,
    // isValidSignature is only reachable on an input whose prevout is known.
    (this.output as Output).script,
    (this.output as Output).satoshisBN
  )
}

/**
 * @returns true if this is a coinbase input (represents no input)
 */
Input.prototype.isNull = function (this: Input): boolean {
  return this.prevTxId.toString('hex') === '0000000000000000000000000000000000000000000000000000000000000000' &&
    this.outputIndex === 0xffffffff
}

Input.prototype._estimateSize = function (this: Input): number {
  return (this.toBufferWriter() as { toBuffer: () => Buffer }).toBuffer().length
}

export = Input
