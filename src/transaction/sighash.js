'use strict'

const buffer = require('buffer')

const Signature = require('../crypto/signature')
const Script = require('../script')
const Output = require('./output')
const BufferReader = require('../encoding/bufferreader')
const BufferWriter = require('../encoding/bufferwriter')
const BN = require('../crypto/bn')
const Hash = require('../crypto/hash')
const ECDSA = require('../crypto/ecdsa')
const $ = require('../util/preconditions')
const Interpreter = require('../script/interpreter')
const _ = require('../util/_')

const SIGHASH_SINGLE_BUG = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex')
const BITS_64_ON = 'ffffffffffffffff'

// By default, we sign with sighash_forkid
// Read lazily: Interpreter is part of the script <-> transaction import
// cycle, so dereferencing it during module evaluation is unsafe under ESM,
// where the binding may still be in its temporal dead zone.
const defaultSignFlags = () => Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID

const sighashPreimageForForkId = function (transaction, sighashType, inputNumber, subscript, satoshisBN) {
  const input = transaction.inputs[inputNumber]
  $.checkArgument(
    satoshisBN instanceof BN,
    'For ForkId=0 signatures, satoshis or complete input must be provided'
  )

  function GetPrevoutHash (tx) {
    const writer = new BufferWriter()

    _.each(tx.inputs, function (input) {
      writer.writeReverse(input.prevTxId)
      writer.writeUInt32LE(input.outputIndex)
    })

    const buf = writer.toBuffer()
    const ret = Hash.sha256sha256(buf)
    return ret
  }

  function GetSequenceHash (tx) {
    const writer = new BufferWriter()

    _.each(tx.inputs, function (input) {
      writer.writeUInt32LE(input.sequenceNumber)
    })

    const buf = writer.toBuffer()
    const ret = Hash.sha256sha256(buf)
    return ret
  }

  function GetOutputsHash (tx, n) {
    const writer = new BufferWriter()

    if (_.isUndefined(n)) {
      _.each(tx.outputs, function (output) {
        output.toBufferWriter(writer)
      })
    } else {
      tx.outputs[n].toBufferWriter(writer)
    }

    const buf = writer.toBuffer()
    const ret = Hash.sha256sha256(buf)
    return ret
  }

  let hashPrevouts = Buffer.alloc(32)
  let hashSequence = Buffer.alloc(32)
  let hashOutputs = Buffer.alloc(32)

  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY)) {
    hashPrevouts = GetPrevoutHash(transaction)
  }

  if (!(sighashType & Signature.SIGHASH_ANYONECANPAY) &&
    (sighashType & 31) !== Signature.SIGHASH_SINGLE &&
    (sighashType & 31) !== Signature.SIGHASH_NONE) {
    hashSequence = GetSequenceHash(transaction)
  }

  if ((sighashType & 31) !== Signature.SIGHASH_SINGLE && (sighashType & 31) !== Signature.SIGHASH_NONE) {
    hashOutputs = GetOutputsHash(transaction)
  } else if ((sighashType & 31) === Signature.SIGHASH_SINGLE && inputNumber < transaction.outputs.length) {
    hashOutputs = GetOutputsHash(transaction, inputNumber)
  }

  const writer = new BufferWriter()

  // Version
  writer.writeInt32LE(transaction.version)

  // Input prevouts/nSequence (none/all, depending on flags)
  writer.write(hashPrevouts)
  writer.write(hashSequence)

  //  outpoint (32-byte hash + 4-byte little endian)
  writer.writeReverse(input.prevTxId)
  writer.writeUInt32LE(input.outputIndex)

  // scriptCode of the input (serialized as scripts inside CTxOuts)
  writer.writeVarintNum(subscript.toBuffer().length)
  writer.write(subscript.toBuffer())

  // value of the output spent by this input (8-byte little endian)
  writer.writeUInt64LEBN(satoshisBN)

  // nSequence of the input (4-byte little endian)
  const sequenceNumber = input.sequenceNumber
  writer.writeUInt32LE(sequenceNumber)

  // Outputs (none/one/all, depending on flags)
  writer.write(hashOutputs)

  // Locktime
  writer.writeUInt32LE(transaction.nLockTime)

  // sighashType
  writer.writeUInt32LE(sighashType >>> 0)

  const buf = writer.toBuffer()
  return buf
}

/**
 * Returns a buffer with the which is hashed with sighash that needs to be signed
 * for OP_CHECKSIG.
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Script} subscript the script that will be signed
 * @param {satoshisBN} input's amount (for  ForkId signatures)
 *
 */
const sighashPreimage = function sighashPreimage (transaction, sighashType, inputNumber, subscript, satoshisBN, flags) {
  const Transaction = require('./transaction')
  const Input = require('./input')

  if (_.isUndefined(flags)) {
    flags = defaultSignFlags()
  }

  // Copy transaction
  const txcopy = Transaction.shallowCopy(transaction)

  // Copy script
  subscript = new Script(subscript)

  if (flags & Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION) {
    // Legacy chain's value for fork id must be of the form 0xffxxxx.
    // By xoring with 0xdead, we ensure that the value will be different
    // from the original one, even if it already starts with 0xff.
    const forkValue = sighashType >> 8
    const newForkValue = 0xff0000 | (forkValue ^ 0xdead)
    sighashType = (newForkValue << 8) | (sighashType & 0xff)
  }

  if ((sighashType & Signature.SIGHASH_FORKID) && (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID)) {
    return sighashPreimageForForkId(txcopy, sighashType, inputNumber, subscript, satoshisBN)
  }

  // For no ForkId sighash, separators need to be removed.
  subscript.removeCodeseparators()

  let i

  for (i = 0; i < txcopy.inputs.length; i++) {
    // Blank signatures for other inputs
    txcopy.inputs[i] = new Input(txcopy.inputs[i]).setScript(Script.empty())
  }

  txcopy.inputs[inputNumber] = new Input(txcopy.inputs[inputNumber]).setScript(subscript)

  if ((sighashType & 31) === Signature.SIGHASH_NONE ||
    (sighashType & 31) === Signature.SIGHASH_SINGLE) {
    // clear all sequenceNumbers
    for (i = 0; i < txcopy.inputs.length; i++) {
      if (i !== inputNumber) {
        txcopy.inputs[i].sequenceNumber = 0
      }
    }
  }

  if ((sighashType & 31) === Signature.SIGHASH_NONE) {
    txcopy.outputs = []
  } else if ((sighashType & 31) === Signature.SIGHASH_SINGLE) {
    // The SIGHASH_SINGLE bug.
    // https://bitcointalk.org/index.php?topic=260595.0
    if (inputNumber >= txcopy.outputs.length) {
      return SIGHASH_SINGLE_BUG
    }

    txcopy.outputs.length = inputNumber + 1

    for (i = 0; i < inputNumber; i++) {
      txcopy.outputs[i] = new Output({
        satoshis: BN.fromBuffer(buffer.Buffer.from(BITS_64_ON, 'hex')),
        script: Script.empty()
      })
    }
  }

  if (sighashType & Signature.SIGHASH_ANYONECANPAY) {
    txcopy.inputs = [txcopy.inputs[inputNumber]]
  }

  const buf = new BufferWriter()
    .write(txcopy.toBuffer())
    .writeInt32LE(sighashType)
    .toBuffer()
  return buf
}

/**
 * Returns a buffer of length 32 bytes with the hash that needs to be signed
 * for OP_CHECKSIG.
 *
 * @name Signing.sighash
 * @param {Transaction} transaction the transaction to sign
 * @param {number} sighashType the type of the hash
 * @param {number} inputNumber the input index for the signature
 * @param {Script} subscript the script that will be signed
 * @param {satoshisBN} input's amount (for  ForkId signatures)
 *
 */
const sighash = function sighash (transaction, sighashType, inputNumber, subscript, satoshisBN, flags) {
  const preimage = sighashPreimage(transaction, sighashType, inputNumber, subscript, satoshisBN, flags)
  if (preimage.compare(SIGHASH_SINGLE_BUG) === 0) return preimage
  let ret = Hash.sha256sha256(preimage)
  ret = new BufferReader(ret).readReverse()
  return ret
}

/**
 * Create a signature
 *
 * @name Signing.sign
 * @param {Transaction} transaction
 * @param {PrivateKey} privateKey
 * @param {number} sighash
 * @param {number} inputIndex
 * @param {Script} subscript
 * @param {satoshisBN} input's amount
 * @return {Signature}
 */
function sign (transaction, privateKey, sighashType, inputIndex, subscript, satoshisBN, flags) {
  const hashbuf = sighash(transaction, sighashType, inputIndex, subscript, satoshisBN, flags)

  const sig = ECDSA.sign(hashbuf, privateKey, 'little').set({
    nhashtype: sighashType
  })
  return sig
}

/**
 * Verify a signature
 *
 * @name Signing.verify
 * @param {Transaction} transaction
 * @param {Signature} signature
 * @param {PublicKey} publicKey
 * @param {number} inputIndex
 * @param {Script} subscript
 * @param {satoshisBN} input's amount
 * @param {flags} verification flags
 * @return {boolean}
 */
function verify (transaction, signature, publicKey, inputIndex, subscript, satoshisBN, flags) {
  $.checkArgument(!_.isUndefined(transaction))
  $.checkArgument(!_.isUndefined(signature) && !_.isUndefined(signature.nhashtype))
  const hashbuf = sighash(transaction, signature.nhashtype, inputIndex, subscript, satoshisBN, flags)
  return ECDSA.verify(hashbuf, signature, publicKey, 'little')
}

/**
 * @namespace Signing
 */
module.exports = {
  sighashPreimage,
  sighash,
  sign,
  verify
}
