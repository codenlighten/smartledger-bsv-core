'use strict'

import _ = require('../util/_')

import Script = require('./script')
import Opcode = require('../opcode')
import BN = require('../crypto/bn')
import Hash = require('../crypto/hash')
import Signature = require('../crypto/signature')
import cloneDeep = require('clone-deep')
import type { Interpreter, InterpreterConstructor, InterpreterState, InterpreterFlags, StepInfo, ScriptLimits } from './interpreter.types'
import type Transaction = require('../transaction')
import type { Script as ScriptType, ScriptChunk } from './script.types'
import type { PublicKeyConstructor } from '../publickey.types'

// publickey is in this cycle, so it resolves on demand.
const publicKeyClass = (): PublicKeyConstructor => require('../publickey')

// NOTE ON THE `as ScriptChunk` / `as Buffer` CASTS BELOW: the interpreter
// indexes chunks and the stack constantly, always after an explicit bounds or
// depth check (`stack.length < 2`, `pc < chunks.length`, ...). TypeScript
// cannot carry those checks to the index, so the casts state what the guard
// already established. They are erased, so an out-of-range access still
// behaves exactly as it did.

/**
 * Bitcoin transactions contain scripts. Each input has a script called the
 * scriptSig, and each output has a script called the scriptPubkey. To validate
 * an input, the input's script is concatenated with the referenced output script,
 * and the result is executed. If at the end of execution the stack contains a
 * "true" value, then the transaction is valid.
 *
 * The primary way to use this class is via the verify function.
 * e.g., Interpreter().verify( ... );
 */
const Interpreter = function Interpreter (this: Interpreter, obj?: unknown) {
  if (!(this instanceof Interpreter)) {
    return new (Interpreter as unknown as InterpreterConstructor)(obj as InterpreterState)
  }
  if (obj) {
    this.initialize()
    this.set(obj as Record<string, unknown>)
  } else {
    this.initialize()
  }
} as unknown as InterpreterConstructor

/**
 * Verifies a Script by executing it and returns true if it is valid.
 * This function needs to be provided with the scriptSig and the scriptPubkey
 * separately.
 * @param {Script} scriptSig - the script's first part (corresponding to the tx input)
 * @param {Script} scriptPubkey - the script's last part (corresponding to the tx output)
 * @param {Transaction=} tx - the Transaction containing the scriptSig in one input (used
 *    to check signature validity for some opcodes like OP_CHECKSIG)
 * @param {number} nin - index of the transaction input containing the scriptSig verified.
 * @param {number} flags - evaluation flags. See Interpreter.SCRIPT_* constants
 * @param {number} satoshisBN - amount in satoshis of the input to be verified (when FORKID signhash is used)
 *
 * Translated from bitcoind's VerifyScript
 */
Interpreter.prototype.verify = function (this: Interpreter, scriptSig: Script, scriptPubkey: Script, tx?: Transaction, nin?: number, flags?: number, satoshisBN?: BN) {
  const Transaction = require('../transaction')

  if (_.isUndefined(tx)) {
    tx = new Transaction()
  }
  if (_.isUndefined(nin)) {
    nin = 0
  }
  if (_.isUndefined(flags)) {
    flags = 0
  }

  // If FORKID is enabled, we also ensure strict encoding.
  if (flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID) {
    flags |= Interpreter.SCRIPT_VERIFY_STRICTENC

    // If FORKID is enabled, we need the input amount.
    if (!satoshisBN) {
      throw new Error('internal error - need satoshisBN to verify FORKID transactions')
    }
  }

  this.set({
    script: scriptSig,
    tx,
    nin,
    flags,
    satoshisBN
  })
  let stackCopy: Buffer[] = []

  if ((flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY) !== 0 && !scriptSig.isPushOnly()) {
    this.errstr = 'SCRIPT_ERR_SIG_PUSHONLY'
    return false
  }

  // evaluate scriptSig
  if (!this.evaluate()) {
    return false
  }

  if (flags & Interpreter.SCRIPT_VERIFY_P2SH) {
    stackCopy = this.stack.slice()
  }

  const stack = this.stack
  this.initialize()
  this.set({
    script: scriptPubkey,
    stack,
    tx,
    nin,
    flags,
    satoshisBN
  })

  // evaluate scriptPubkey
  if (!this.evaluate()) {
    return false
  }

  if (this.stack.length === 0) {
    this.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT'
    return false
  }

  const buf = (this.stack[this.stack.length - 1] as Buffer)
  if (!Interpreter.castToBool(buf)) {
    this.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK'
    return false
  }

  // Additional validation for spend-to-script-hash transactions:
  if ((flags & Interpreter.SCRIPT_VERIFY_P2SH) && scriptPubkey.isScriptHashOut()) {
    // scriptSig must be literals-only or validation fails
    if (!scriptSig.isPushOnly()) {
      this.errstr = 'SCRIPT_ERR_SIG_PUSHONLY'
      return false
    }

    // stackCopy cannot be empty here, because if it was the
    // P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
    // an empty stack and the EvalScript above would return false.
    if (stackCopy.length === 0) {
      throw new Error('internal error - stack copy empty')
    }

    const redeemScriptSerialized = stackCopy[stackCopy.length - 1]
    const redeemScript = Script.fromBuffer(redeemScriptSerialized as Buffer)
    stackCopy.pop()

    this.initialize()
    this.set({
      script: redeemScript,
      stack: stackCopy,
      tx,
      nin,
      flags,
      satoshisBN
    })

    // evaluate redeemScript
    if (!this.evaluate()) {
      return false
    }

    if (stackCopy.length === 0) {
      this.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK'
      return false
    }

    if (!Interpreter.castToBool(stackCopy[stackCopy.length - 1] as Buffer)) {
      this.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK'
      return false
    }
  }

  // The CLEANSTACK check is only performed after potential P2SH evaluation,
  // as the non-P2SH evaluation of a P2SH script will obviously not result in
  // a clean stack (the P2SH inputs remain). The same holds for witness
  // evaluation.
  if ((flags & Interpreter.SCRIPT_VERIFY_CLEANSTACK) !== 0) {
    // Disallow CLEANSTACK without P2SH, as otherwise a switch
    // CLEANSTACK->P2SH+CLEANSTACK would be possible, which is not a
    // softfork (and P2SH should be one).
    if ((flags & Interpreter.SCRIPT_VERIFY_P2SH) === 0) {
      throw new Error('internal error - CLEANSTACK without P2SH')
    }

    if (stackCopy.length !== 1) {
      this.errstr = 'SCRIPT_ERR_CLEANSTACK'
      return false
    }
  }

  return true
}

export = Interpreter

Interpreter.prototype.initialize = function (this: Interpreter, obj?: InterpreterState) {
  this.stack = []
  this.altstack = []
  this.pc = 0
  this.pbegincodehash = 0
  this.nOpCount = 0
  this.vfExec = []
  this.errstr = ''
  this.flags = 0
}

Interpreter.prototype.set = function (this: Interpreter, obj: InterpreterState) {
  this.script = obj.script || this.script
  this.tx = obj.tx || this.tx
  this.nin = typeof obj.nin !== 'undefined' ? obj.nin : this.nin!
  this.satoshisBN = obj.satoshisBN || this.satoshisBN
  this.stack = obj.stack || this.stack
  this.altstack = obj.altstack || this.altstack
  this.pc = typeof obj.pc !== 'undefined' ? obj.pc : this.pc
  this.pbegincodehash = typeof obj.pbegincodehash !== 'undefined' ? obj.pbegincodehash : this.pbegincodehash
  this.nOpCount = typeof obj.nOpCount !== 'undefined' ? obj.nOpCount : this.nOpCount
  this.vfExec = obj.vfExec || this.vfExec
  this.errstr = obj.errstr || this.errstr
  this.flags = typeof obj.flags !== 'undefined' ? obj.flags : this.flags
}

Interpreter.true = Buffer.from([1])
Interpreter.false = Buffer.from([])

Interpreter.MAX_SCRIPT_ELEMENT_SIZE = 520
Interpreter.MAXIMUM_ELEMENT_SIZE = 4
// Maximum number of non-push opcodes per script. Pre-Genesis consensus is 201;
// post-Genesis BSV removed this limit. Exposed as a constant (instead of a magic
// number) so applications can opt into post-Genesis rules — e.g. OP_PUSH_TX
// covenants, which need a few hundred opcodes — without forking the interpreter.
Interpreter.MAX_OPS_PER_SCRIPT = 201
// Maximum total serialized script size. Pre-Genesis consensus is 10,000 bytes;
// post-Genesis BSV removed this limit too. It was previously a literal inside
// evaluate(), so `useGenesisLimits()` could not lift it and any script over 10 KB —
// a large 1Sat Ordinals inscription, for instance — failed SCRIPT_ERR_SCRIPT_SIZE
// no matter what the caller asked for.
Interpreter.MAX_SCRIPT_SIZE = 10000

Interpreter.LOCKTIME_THRESHOLD = 500000000
Interpreter.LOCKTIME_THRESHOLD_BN = new BN(Interpreter.LOCKTIME_THRESHOLD)

/**
 * Opt into post-Genesis BSV consensus limits: effectively no caps on stack
 * element size, script-number width, opcode count, or total script size.
 * Pre-Genesis defaults (520 / 4 / 201 / 10,000) remain the out-of-the-box
 * behavior; call this before verify() to run modern covenants such as
 * OP_PUSH_TX, or to evaluate a script larger than 10 KB such as a sizeable
 * 1Sat Ordinals inscription.
 *
 * IMPORTANT: this mutates static properties on the Interpreter constructor
 * and therefore affects EVERY subsequent `new Interpreter()` in this
 * process. Treat it as a process-wide setting — call it once at app
 * startup, not per-request. There is no per-instance form.
 *
 * The default `max` (`0x7fffffff`, ~2 GB) is effectively unbounded. If you
 * are verifying scripts from untrusted sources, pass a ceiling matched to
 * your workload to prevent memory-exhaustion via oversized pushes —
 * 64 KB covers every covenant pattern seen in production:
 *
 *   bsv.Script.Interpreter.useGenesisLimits(64 * 1024)
 *
 * @param {number} [max=0x7fffffff] Ceiling applied to all four caps.
 * @returns {Interpreter} the Interpreter constructor (for chaining)
 */
Interpreter.useGenesisLimits = function (max?: number) {
  max = max || 0x7fffffff
  Interpreter.MAX_SCRIPT_ELEMENT_SIZE = max
  Interpreter.MAXIMUM_ELEMENT_SIZE = max
  Interpreter.MAX_OPS_PER_SCRIPT = max
  Interpreter.MAX_SCRIPT_SIZE = max
  return Interpreter
}

/** The four consensus caps, as a plain object. */
Interpreter.getLimits = function () {
  return {
    maxScriptElementSize: Interpreter.MAX_SCRIPT_ELEMENT_SIZE,
    maximumElementSize: Interpreter.MAXIMUM_ELEMENT_SIZE,
    maxOpsPerScript: Interpreter.MAX_OPS_PER_SCRIPT,
    maxScriptSize: Interpreter.MAX_SCRIPT_SIZE
  }
}

/**
 * Restore caps captured by `getLimits()`. Because the caps are process-wide statics,
 * anything that raises them must put them back or it silently changes the rules for
 * unrelated code later in the same process — which is exactly how a test that opts
 * into Genesis limits can make a pre-Genesis consensus fixture pass. Pair the two:
 *
 *   var saved = Interpreter.getLimits()
 *   Interpreter.useGenesisLimits()
 *   ...
 *   Interpreter.setLimits(saved)
 *
 * @param {object} limits as returned by getLimits()
 * @returns {Interpreter} the Interpreter constructor (for chaining)
 */
Interpreter.setLimits = function (limits?: ScriptLimits) {
  limits = limits ?? {}
  if (limits.maxScriptElementSize != null) Interpreter.MAX_SCRIPT_ELEMENT_SIZE = limits.maxScriptElementSize
  if (limits.maximumElementSize != null) Interpreter.MAXIMUM_ELEMENT_SIZE = limits.maximumElementSize
  if (limits.maxOpsPerScript != null) Interpreter.MAX_OPS_PER_SCRIPT = limits.maxOpsPerScript
  if (limits.maxScriptSize != null) Interpreter.MAX_SCRIPT_SIZE = limits.maxScriptSize
  return Interpreter
}

// flags taken from bitcoind
// bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
Interpreter.SCRIPT_VERIFY_NONE = 0

// Evaluate P2SH subscripts (softfork safe, BIP16).
Interpreter.SCRIPT_VERIFY_P2SH = (1 << 0)

// Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
// Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
// skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
Interpreter.SCRIPT_VERIFY_STRICTENC = (1 << 1)

// Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
Interpreter.SCRIPT_VERIFY_DERSIG = (1 << 2)

// Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
// (softfork safe, BIP62 rule 5).
Interpreter.SCRIPT_VERIFY_LOW_S = (1 << 3)

// verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
Interpreter.SCRIPT_VERIFY_NULLDUMMY = (1 << 4)

// Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
Interpreter.SCRIPT_VERIFY_SIGPUSHONLY = (1 << 5)

// Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
// pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
// any other push causes the script to fail (BIP62 rule 3).
// In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
// (softfork safe)
Interpreter.SCRIPT_VERIFY_MINIMALDATA = (1 << 6)

// Discourage use of NOPs reserved for upgrades (NOP1-10)
//
// Provided so that nodes can avoid accepting or mining transactions
// containing executed NOP's whose meaning may change after a soft-fork,
// thus rendering the script invalid; with this flag set executing
// discouraged NOPs fails the script. This verification flag will never be
// a mandatory flag applied to scripts in a block. NOPs that are not
// executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1 << 7)

// Require that only a single stack element remains after evaluation. This
// changes the success criterion from "At least one stack element must
// remain, and when interpreted as a boolean, it must be true" to "Exactly
// one stack element must remain, and when interpreted as a boolean, it must
// be true".
// (softfork safe, BIP62 rule 6)
// Note: CLEANSTACK should never be used without P2SH or WITNESS.
Interpreter.SCRIPT_VERIFY_CLEANSTACK = (1 << 8)

// CLTV See BIP65 for details.
Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1 << 9)

// support CHECKSEQUENCEVERIFY opcode
//
// See BIP112 for details
Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1 << 10)

// Segwit script only: Require the argument of OP_IF/NOTIF to be exactly
// 0x01 or empty vector
//
Interpreter.SCRIPT_VERIFY_MINIMALIF = (1 << 13)

// Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
//
Interpreter.SCRIPT_VERIFY_NULLFAIL = (1 << 14)

// Public keys in scripts must be compressed
Interpreter.SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE = (1 << 15)

// Do we accept signature using SIGHASH_FORKID
//
Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID = (1 << 16)

// Chronicle: honour SIGHASH_CHRONICLE (0x20) as the selector for the Original
// Transaction Digest Algorithm.
//
// OFF BY DEFAULT, and that is not caution for its own sake. Before Chronicle
// the 0x20 bit carries no meaning, so signatures already exist whose sighash
// type happens to have it set and which are BIP-143 signatures. Honouring the
// bit unconditionally reinterprets every one of them as OTDA and breaks them —
// 252 of this repository's own tests, when it was tried.
//
// Same shape as SCRIPT_ENABLE_SIGHASH_FORKID and useGenesisLimits(): the
// pre-upgrade rules remain the default and a caller opts in.
Interpreter.SCRIPT_ENABLE_CHRONICLE = (1 << 20)

// Do we accept activate replay protection using a different fork id.
//
Interpreter.SCRIPT_ENABLE_REPLAY_PROTECTION = (1 << 17)

// Enable new opcodes.
//
Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES = (1 << 18)

// Are the Magnetic upgrade opcodes enabled?
//
Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES = (1 << 19)

/* Below flags apply in the context of BIP 68 */
/**
 * If this flag set, CTxIn::nSequence is NOT interpreted as a relative
 * lock-time.
 */
Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)

/**
 * If CTxIn::nSequence encodes a relative lock-time and this flag is set,
 * the relative lock-time has units of 512 seconds, otherwise it specifies
 * blocks with a granularity of 1.
 */
Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)

/**
 * If CTxIn::nSequence encodes a relative lock-time, this mask is applied to
 * extract that lock-time from the sequence field.
 */
Interpreter.SEQUENCE_LOCKTIME_MASK = 0x0000ffff

Interpreter.castToBool = function (buf: Buffer) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) {
      // can be negative zero
      if (i === buf.length - 1 && buf[i] === 0x80) {
        return false
      }
      return true
    }
  }
  return false
}

/**
 * Translated from bitcoind's CheckSignatureEncoding
 */
Interpreter.prototype.checkSignatureEncoding = function (this: Interpreter, buf: Buffer) {
  let sig

  // Empty signature. Not strictly DER encoded, but allowed to provide a
  // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
  if (buf.length === 0) {
    return true
  }

  if ((this.flags & (Interpreter.SCRIPT_VERIFY_DERSIG | Interpreter.SCRIPT_VERIFY_LOW_S | Interpreter.SCRIPT_VERIFY_STRICTENC)) !== 0 && !Signature.isTxDER(buf)) {
    this.errstr = 'SCRIPT_ERR_SIG_DER_INVALID_FORMAT'
    return false
  } else if ((this.flags & Interpreter.SCRIPT_VERIFY_LOW_S) !== 0) {
    sig = Signature.fromTxFormat(buf)
    if (!sig.hasLowS()) {
      this.errstr = 'SCRIPT_ERR_SIG_DER_HIGH_S'
      return false
    }
  } else if ((this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) !== 0) {
    sig = Signature.fromTxFormat(buf)
    if (!sig.hasDefinedHashtype()) {
      this.errstr = 'SCRIPT_ERR_SIG_HASHTYPE'
      return false
    }

    if (!(this.flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID) &&
        ((sig.nhashtype as number) & Signature.SIGHASH_FORKID)) {
      this.errstr = 'SCRIPT_ERR_ILLEGAL_FORKID'
      return false
    }

    if ((this.flags & Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID) &&
        !((sig.nhashtype as number) & Signature.SIGHASH_FORKID)) {
      this.errstr = 'SCRIPT_ERR_MUST_USE_FORKID'
      return false
    }
  }

  return true
}

/**
 * Translated from bitcoind's CheckPubKeyEncoding
 */
Interpreter.prototype.checkPubkeyEncoding = function (this: Interpreter, buf: Buffer) {
  if ((this.flags & Interpreter.SCRIPT_VERIFY_STRICTENC) !== 0 && !publicKeyClass().isValid(buf)) {
    this.errstr = 'SCRIPT_ERR_PUBKEYTYPE'
    return false
  }
  return true
}

/**
  *
  * Check the buffer is minimally encoded (see https://github.com/bitcoincashorg/spec/blob/master/may-2018-reenabled-opcodes.md#op_bin2num)
  *
  *
  */

Interpreter._isMinimallyEncoded = function (buf: Buffer, nMaxNumSize?: number) {
  nMaxNumSize = nMaxNumSize || Interpreter.MAXIMUM_ELEMENT_SIZE
  if (buf.length > nMaxNumSize) {
    return false
  }

  if (buf.length > 0) {
    // Check that the number is encoded with the minimum possible number
    // of bytes.
    //
    // If the most-significant-byte - excluding the sign bit - is zero
    // then we're not minimal. Note how this test also rejects the
    // negative-zero encoding, 0x80.
    if ((buf[buf.length - 1]! & 0x7f) === 0) {
      // One exception: if there's more than one byte and the most
      // significant bit of the second-most-significant-byte is set it
      // would conflict with the sign bit. An example of this case is
      // +-255, which encode to 0xff00 and 0xff80 respectively.
      // (big-endian).
      if (buf.length <= 1 || (buf[buf.length - 2]! & 0x80) === 0) {
        return false
      }
    }
  }
  return true
}

/**
  *
  * minimally encode the buffer content
  *
  * @param {number} nMaxNumSize (max allowed size)
  */
Interpreter._minimallyEncode = function (buf: Buffer) {
  if (buf.length === 0) {
    return buf
  }

  // If the last byte is not 0x00 or 0x80, we are minimally encoded.
  const last = buf[buf.length - 1]!
  if (last & 0x7f) {
    return buf
  }

  // If the script is one byte long, then we have a zero, which encodes as an
  // empty array.
  if (buf.length === 1) {
    return Buffer.from('')
  }

  // If the next byte has it sign bit set, then we are minimaly encoded.
  if (buf[buf.length - 2]! & 0x80) {
    return buf
  }

  // We are not minimally encoded, we need to figure out how much to trim.
  for (let i = buf.length - 1; i > 0; i--) {
    // We found a non zero byte, time to encode.
    if (buf[i - 1]! !== 0) {
      if (buf[i - 1]! & 0x80) {
        // We found a byte with it sign bit set so we need one more
        // byte.
        buf[i++] = last!
      } else {
        // the sign bit is clear, we can use it.
        buf[i - 1] = buf[i - 1]! | last!
      }

      return buf.slice(0, i)
    }
  }

  // If we found the whole thing is zeros, then we have a zero.
  return Buffer.from('')
}

/**
 * Based on bitcoind's EvalScript function, with the inner loop moved to
 * Interpreter.prototype.step()
 * bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
 */
Interpreter.prototype.evaluate = function (this: Interpreter) {
  if (this.script!.toBuffer().length > Interpreter.MAX_SCRIPT_SIZE) {
    this.errstr = 'SCRIPT_ERR_SCRIPT_SIZE'
    return false
  }

  try {
    while (this.pc < this.script!.chunks.length) {
      const thisStep = { pc: this.pc, opcode: Opcode.fromNumber((this.script!.chunks[this.pc] as ScriptChunk).opcodenum) }
      const fSuccess = this.step()
      if (!fSuccess) {
        return false
      }
      this._callbackStep(thisStep)
    }

    // Size limits
    if (this.stack.length + this.altstack.length > 1000) {
      this.errstr = 'SCRIPT_ERR_STACK_SIZE'
      return false
    }
  } catch (e) {
    this.errstr = 'SCRIPT_ERR_UNKNOWN_ERROR: ' + e
    return false
  }

  if (this.vfExec.length > 0) {
    this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
    return false
  }

  return true
}

Interpreter.prototype._callbackStep = function (this: Interpreter, thisStep: StepInfo) {
  if (typeof this.stepListener === 'function') {
    try {
      this.stepListener(thisStep, cloneDeep(this.stack, true), cloneDeep(this.altstack, true))
    } catch (err) {
      console.log(`Error in Step callback:${err}`)
    }
  }
}

/**
 * Checks a locktime parameter with the transaction's locktime.
 * There are two times of nLockTime: lock-by-blockheight and lock-by-blocktime,
 * distinguished by whether nLockTime < LOCKTIME_THRESHOLD = 500000000
 *
 * See the corresponding code on bitcoin core:
 * https://github.com/bitcoin/bitcoin/blob/ffd75adce01a78b3461b3ff05bcc2b530a9ce994/src/script/interpreter.cpp#L1129
 *
 * @param {BN} nLockTime the locktime read from the script
 * @return {boolean} true if the transaction's locktime is less than or equal to
 *                   the transaction's locktime
 */
Interpreter.prototype.checkLockTime = function (this: Interpreter, nLockTime: BN) {
  // We want to compare apples to apples, so fail the script
  // unless the type of nLockTime being tested is the same as
  // the nLockTime in the transaction.
  if (!(
    (this.tx!.nLockTime < Interpreter.LOCKTIME_THRESHOLD && nLockTime.lt(Interpreter.LOCKTIME_THRESHOLD_BN)) ||
    (this.tx!.nLockTime >= Interpreter.LOCKTIME_THRESHOLD && nLockTime.gte(Interpreter.LOCKTIME_THRESHOLD_BN))
  )) {
    return false
  }

  // Now that we know we're comparing apples-to-apples, the
  // comparison is a simple numeric one.
  if (nLockTime.gt(new BN(this.tx!.nLockTime))) {
    return false
  }

  // Finally the nLockTime feature can be disabled and thus
  // CHECKLOCKTIMEVERIFY bypassed if every txin has been
  // finalized by setting nSequence to maxint. The
  // transaction would be allowed into the blockchain, making
  // the opcode ineffective.
  //
  // Testing if this vin is not final is sufficient to
  // prevent this condition. Alternatively we could test all
  // inputs, but testing just this input minimizes the data
  // required to prove correct CHECKLOCKTIMEVERIFY execution.
  if (this.tx!.inputs[this.nin!]!.isFinal()) {
    return false
  }

  return true
}

/**
 * Checks a sequence parameter with the transaction's sequence.
 * @param {BN} nSequence the sequence read from the script
 * @return {boolean} true if the transaction's sequence is less than or equal to
 *                   the transaction's sequence
 */
Interpreter.prototype.checkSequence = function (this: Interpreter, nSequence: BN) {
  // Relative lock times are supported by comparing the passed in operand to
  // the sequence number of the input.
  const txToSequence = this.tx!.inputs[this.nin!]!.sequenceNumber

  // Fail if the transaction's version number is not set high enough to
  // trigger BIP 68 rules.
  if (this.tx!.version < 2) {
    return false
  }

  // Sequence numbers with their most significant bit set are not consensus
  // constrained. Testing that the transaction's sequence number do not have
  // this bit set prevents using this property to get around a
  // CHECKSEQUENCEVERIFY check.
  if (txToSequence & Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG) {
    return false
  }

  // Mask off any bits that do not have consensus-enforced meaning before
  // doing the integer comparisons
  const nLockTimeMask =
        Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG | Interpreter.SEQUENCE_LOCKTIME_MASK
  const txToSequenceMasked = new BN(txToSequence & nLockTimeMask)
  // BUG, PRESERVED: bn.js `and` takes a BN, and `nLockTimeMask` is a plain
  // number, so this throws `num.clone is not a function`. The interpreter's
  // try/catch swallows it and reports SCRIPT_ERR_UNKNOWN_ERROR, which makes
  // OP_CHECKSEQUENCEVERIFY unusable — every CSV script fails verification with
  // a misleading error. The fix is `nSequence.and(new BN(nLockTimeMask))`.
  // The line above already does the same masking correctly, with JS numbers.
  // Left as-is: this pass changes no behaviour. Recorded separately.
  const nSequenceMasked = nSequence.and(nLockTimeMask as unknown as BN)

  // There are two kinds of nSequence: lock-by-blockheight and
  // lock-by-blocktime, distinguished by whether nSequenceMasked <
  // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
  //
  // We want to compare apples to apples, so fail the script unless the type
  // of nSequenceMasked being tested is the same as the nSequenceMasked in the
  // transaction.
  const SEQUENCE_LOCKTIME_TYPE_FLAG_BN = new BN(Interpreter.SEQUENCE_LOCKTIME_TYPE_FLAG)

  if (!((txToSequenceMasked.lt(SEQUENCE_LOCKTIME_TYPE_FLAG_BN) &&
           nSequenceMasked.lt(SEQUENCE_LOCKTIME_TYPE_FLAG_BN)) ||
          (txToSequenceMasked.gte(SEQUENCE_LOCKTIME_TYPE_FLAG_BN) &&
           nSequenceMasked.gte(SEQUENCE_LOCKTIME_TYPE_FLAG_BN)))) {
    return false
  }

  // Now that we know we're comparing apples-to-apples, the comparison is a
  // simple numeric one.
  if (nSequenceMasked.gt(txToSequenceMasked)) {
    return false
  }
  return true
}

function padBufferToSize (buf: Buffer, len: number): Buffer {
  let b = buf
  while (b.length < len) {
    b = Buffer.concat([Buffer.from([0x00]), b])
  }
  return b
}

/**
 * Based on the inner loop of bitcoind's EvalScript function
 * bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
 */
Interpreter.prototype.step = function (this: Interpreter) {
  const self = this

  /**
   * Peek at the stack relative to the top: stacktop(-1) is the top element.
   *
   * Returns Buffer, not Buffer | undefined: every call site is preceded by an
   * explicit depth check ("if (this.stack.length < N) { errstr = ...; return
   * false }"), which TypeScript cannot carry to the index. An out-of-range
   * peek still yields undefined at runtime, exactly as before.
   */
  function stacktop (i: number): Buffer {
    return self.stack[self.stack.length + i] as Buffer
  }

  function isOpcodeDisabled (opcode: number): boolean {
    switch (opcode) {
      case Opcode.OP_2MUL:
      case Opcode.OP_2DIV:
        // Chronicle restores both. Until it is enabled they stay disabled, and
        // "disabled" is stronger than "unimplemented": a disabled opcode fails
        // the script even in an UNEXECUTED branch, which is why this lives in
        // isOpcodeDisabled rather than in the evaluation switch.
        if ((self.flags & Interpreter.SCRIPT_ENABLE_CHRONICLE) === 0) {
          return true
        }
        break

      case Opcode.OP_INVERT:
      case Opcode.OP_MUL:
      case Opcode.OP_LSHIFT:
      case Opcode.OP_RSHIFT:
        // Magnetic opcodes - still require flag for backwards compatibility
        if ((self.flags & Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES) === 0) {
          return true
        }
        break

      // Monolith opcodes are now enabled by default in SmartLedger BSV
      // These were activated in May 2018 and are part of standard BSV consensus
      case Opcode.OP_DIV:
      case Opcode.OP_MOD:
      case Opcode.OP_SPLIT:
      case Opcode.OP_CAT:
      case Opcode.OP_AND:
      case Opcode.OP_OR:
      case Opcode.OP_XOR:
      case Opcode.OP_BIN2NUM:
      case Opcode.OP_NUM2BIN:
        // These opcodes are now always enabled - no flag required
        return false

      default:
        break
    }

    return false
  }

  const fRequireMinimal = (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA) !== 0

  // bool fExec = !count(vfExec.begin(), vfExec.end(), false);
  const fExec = (this.vfExec.indexOf(false) === -1)
  // One declaration for the whole opcode switch, as in the original. The
  // definite-assignment assertions say what the switch guarantees: each case
  // assigns before it reads. They are erased, so an unassigned read still
  // produces the same undefined it always did.
  let buf!: Buffer
  let buf1!: Buffer
  let buf2!: Buffer
  let bufSig!: Buffer
  // The remainder are left untyped rather than guessed at: the switch reuses
  // them across opcodes with genuinely different value types, and pinning one
  // would be a fiction. They are candidates for per-case locals in the API
  // pass, which is where that restructuring belongs.
  let spliced: any, n: any, x1: any, x2: any
  let bn: any, bn1: any, bn2: any
  let bufPubkey: any, subscript: any
  let sig, pubkey
  let fValue, fSuccess

  // Read instruction
  // pc is bounds-checked by `while (this.pc < chunks.length)` in evaluate().
  const chunk = this.script!.chunks[this.pc] as ScriptChunk
  this.pc++
  const opcodenum = chunk.opcodenum
  if (_.isUndefined(opcodenum)) {
    this.errstr = 'SCRIPT_ERR_UNDEFINED_OPCODE'
    return false
  }
  if (chunk.buf != null && chunk.buf!.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
    this.errstr = 'SCRIPT_ERR_PUSH_SIZE'
    return false
  }

  // Note how Opcode.OP_RESERVED does not count towards the opcode limit.
  if (opcodenum > Opcode.OP_16 && ++(this.nOpCount) > Interpreter.MAX_OPS_PER_SCRIPT) {
    this.errstr = 'SCRIPT_ERR_OP_COUNT'
    return false
  }

  if (isOpcodeDisabled(opcodenum)) {
    this.errstr = 'SCRIPT_ERR_DISABLED_OPCODE'
    return false
  }

  if (fExec && opcodenum >= 0 && opcodenum <= Opcode.OP_PUSHDATA4) {
    if (fRequireMinimal && !this.script!.checkMinimalPush(this.pc - 1)) {
      this.errstr = 'SCRIPT_ERR_MINIMALDATA'
      return false
    }
    if (!chunk.buf) {
      this.stack.push(Interpreter.false)
    } else if (chunk.len !== chunk.buf!.length) {
      throw new Error(`Length of push value not equal to length of data (${chunk.len},${chunk.buf!.length})`)
    } else {
      this.stack.push(chunk.buf as Buffer)
    }
  } else if (fExec || (Opcode.OP_IF <= opcodenum && opcodenum <= Opcode.OP_ENDIF)) {
    switch (opcodenum) {
      // Push value
      case Opcode.OP_1NEGATE:
      case Opcode.OP_1:
      case Opcode.OP_2:
      case Opcode.OP_3:
      case Opcode.OP_4:
      case Opcode.OP_5:
      case Opcode.OP_6:
      case Opcode.OP_7:
      case Opcode.OP_8:
      case Opcode.OP_9:
      case Opcode.OP_10:
      case Opcode.OP_11:
      case Opcode.OP_12:
      case Opcode.OP_13:
      case Opcode.OP_14:
      case Opcode.OP_15:
      case Opcode.OP_16:
        // ( -- value)
        // ScriptNum bn((int)opcode - (int)(Opcode.OP_1 - 1));
        n = opcodenum - (Opcode.OP_1 - 1)
        buf = new BN(n).toScriptNumBuffer()
        this.stack.push(buf)
        // The result of these opcodes should always be the minimal way to push the data
        // they push, so no need for a CheckMinimalPush here.
        break

        //
        // Control
        //
      case Opcode.OP_NOP:
        break

      case Opcode.OP_NOP2:
      case Opcode.OP_CHECKLOCKTIMEVERIFY:

        if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
          // not enabled; treat as a NOP2
          if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
            this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
            return false
          }
          break
        }

        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        // Note that elsewhere numeric opcodes are limited to
        // operands in the range -2**31+1 to 2**31-1, however it is
        // legal for opcodes to produce results exceeding that
        // range. This limitation is implemented by CScriptNum's
        // default 4-byte limit.
        //
        // If we kept to that limit we'd have a year 2038 problem,
        // even though the nLockTime field in transactions
        // themselves is uint32 which only becomes meaningless
        // after the year 2106.
        //
        // Thus as a special case we tell CScriptNum to accept up
        // to 5-byte bignums, which are good until 2**39-1, well
        // beyond the 2**32-1 limit of the nLockTime field itself.
        var nLockTime = BN.fromScriptNumBuffer((this.stack[this.stack.length - 1] as Buffer), fRequireMinimal, 5)

        // In the rare event that the argument may be < 0 due to
        // some arithmetic being done first, you can always use
        // 0 MAX CHECKLOCKTIMEVERIFY.
        if (nLockTime.lt(new BN(0))) {
          this.errstr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME'
          return false
        }

        // Actually compare the specified lock time with the transaction.
        if (!this.checkLockTime(nLockTime)) {
          this.errstr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME'
          return false
        }
        break

      case Opcode.OP_NOP3:
      case Opcode.OP_CHECKSEQUENCEVERIFY:

        if (!(this.flags & Interpreter.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
          // not enabled; treat as a NOP3
          if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
            this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
            return false
          }
          break
        }

        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        // nSequence, like nLockTime, is a 32-bit unsigned
        // integer field. See the comment in CHECKLOCKTIMEVERIFY
        // regarding 5-byte numeric operands.

        var nSequence = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal, 5)

        // In the rare event that the argument may be < 0 due to
        // some arithmetic being done first, you can always use
        // 0 MAX CHECKSEQUENCEVERIFY.
        if (nSequence.lt(new BN(0))) {
          this.errstr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME'
          return false
        }

        // To provide for future soft-fork extensibility, if the
        // operand has the disabled lock-time flag set,
        // CHECKSEQUENCEVERIFY behaves as a NOP.
        if (((nSequence as any) &
          Interpreter.SEQUENCE_LOCKTIME_DISABLE_FLAG) !== 0) {
          break
        }

        // Actually compare the specified lock time with the transaction.
        if (!this.checkSequence(nSequence)) {
          this.errstr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME'
          return false
        }
        break

      case Opcode.OP_NOP1:
      // OP_NOP4..OP_NOP8 are gone: Chronicle reassigned their bytes to
      // OP_SUBSTR/OP_LEFT/OP_RIGHT/OP_LSHIFTNUM/OP_RSHIFTNUM. These two are
      // all that remain of the upgradable-NOP range.
      case Opcode.OP_NOP9:
      case Opcode.OP_NOP10:
        if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
          this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
          return false
        }
        break

      case Opcode.OP_LSHIFTNUM:
      case Opcode.OP_RSHIFTNUM:
        // Chronicle numeric shifts, ported from SV Node's
        // src/script/interpreter.cpp.
        //
        // Before Chronicle activates for the UTXO these bytes are UPGRADABLE
        // NOPS on the network, not errors — the node does exactly this:
        //
        //   if(!utxo_after_chronicle) {
        //     if(IsDiscourageUpgradableNops(flags))
        //       return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
        //     else break;
        //   }
        //
        // An earlier version here returned SCRIPT_ERR_BAD_OPCODE instead,
        // which made this library REFUSE SCRIPTS THE NETWORK ACCEPTS — the
        // mirror of the bug that previously made them silently succeed.
        if ((this.flags & Interpreter.SCRIPT_ENABLE_CHRONICLE) === 0) {
          if (this.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
            this.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
            return false
          }
          break
        }

        // (x n -- out): the shift COUNT is on top, the value beneath.
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        {
          const maxNumSize = Interpreter.MAXIMUM_ELEMENT_SIZE
          const shiftBn = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal, maxNumSize)
          if (shiftBn.isNeg()) {
            this.errstr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE'
            return false
          }
          this.stack.pop()
          const valueBn = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal, maxNumSize)
          this.stack.pop()

          const shiftBy = shiftBn.toNumber()
          const negative = valueBn.isNeg()
          // Shift the MAGNITUDE and carry the sign. That is what "preserving
          // sign" means: CScriptNum is sign-magnitude, its bignum path being
          // OpenSSL BN_lshift/BN_rshift, and the int64 path spells out the
          // same rule — division truncating toward zero, so -5 RSHIFTNUM 1 is
          // -2, NOT -3. An arithmetic two's-complement shift would floor to
          // -3. This matches OP_DIV and OP_2DIV. bn.js shrn/shln assert on
          // negatives, so operating on abs() is required regardless.
          const magnitude = valueBn.abs()
          let shifted: BN
          if (opcodenum === Opcode.OP_LSHIFTNUM) {
            // Bound the result BEFORE shifting, as CScriptNum does, so an
            // enormous count cannot allocate an enormous number on the way to
            // being rejected.
            const currentSize = valueBn.toScriptNumBuffer().length
            if (currentSize + Math.floor(shiftBy / 8) > maxNumSize) {
              this.errstr = 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'
              return false
            }
            shifted = magnitude.shln(shiftBy)
          } else {
            // Right-shifting by at least the bit length is zero. Checking that
            // first keeps an arbitrarily large count cheap and matches the
            // node, whose int64 path returns 0 for counts >= 64.
            shifted = shiftBy >= magnitude.bitLength() ? new BN(0) : magnitude.shrn(shiftBy)
          }
          if (negative && !shifted.isZero()) {
            shifted = shifted.neg()
          }
          if (shifted.toScriptNumBuffer().length > maxNumSize) {
            this.errstr = 'SCRIPT_ERR_SCRIPTNUM_OVERFLOW'
            return false
          }
          this.stack.push(shifted.toScriptNumBuffer())
        }
        break

      case Opcode.OP_VER:
        // Chronicle: pushes the executing transaction's version.
        if ((this.flags & Interpreter.SCRIPT_ENABLE_CHRONICLE) === 0) {
          this.errstr = 'SCRIPT_ERR_BAD_OPCODE'
          return false
        }
        if (this.tx == null) {
          this.errstr = 'SCRIPT_ERR_UNKNOWN_ERROR'
          return false
        }
        this.stack.push(new BN(this.tx.version).toScriptNumBuffer())
        break

      case Opcode.OP_VERIF:
      case Opcode.OP_VERNOTIF:
        // Chronicle: an IF whose condition is "top of stack equals the
        // executing transaction's version", closed by OP_ENDIF.
        //
        // Before Chronicle these are invalid EVEN IN AN UNEXECUTED BRANCH —
        // the one rule Bitcoin applies to no other opcode — so the flag check
        // deliberately sits outside the fExec guard below, preserving that.
        if ((this.flags & Interpreter.SCRIPT_ENABLE_CHRONICLE) === 0) {
          this.errstr = 'SCRIPT_ERR_BAD_OPCODE'
          return false
        }
        fValue = false
        if (fExec) {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
            return false
          }
          if (this.tx == null) {
            this.errstr = 'SCRIPT_ERR_UNKNOWN_ERROR'
            return false
          }
          // Popping mirrors OP_IF. The spec describes the comparison but not
          // the stack effect; the OP_VERIF/OP_ENDIF form it documents is an
          // IF, and an IF that left its condition behind would unbalance every
          // script using it.
          bn = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal)
          fValue = bn.cmp(new BN(this.tx.version)) === 0
          if (opcodenum === Opcode.OP_VERNOTIF) {
            fValue = !fValue
          }
          this.stack.pop()
        }
        this.vfExec.push(fValue)
        break

      case Opcode.OP_IF:
      case Opcode.OP_NOTIF:
        // <expression> if [statements] [else [statements]] endif
        // bool fValue = false;
        fValue = false
        if (fExec) {
          if (this.stack.length < 1) {
            this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
            return false
          }
          buf = stacktop(-1)

          if (this.flags & Interpreter.SCRIPT_VERIFY_MINIMALIF) {
            if (buf.length > 1) {
              this.errstr = 'SCRIPT_ERR_MINIMALIF'
              return false
            }
            if (buf.length === 1 && buf[0] !== 1) {
              this.errstr = 'SCRIPT_ERR_MINIMALIF'
              return false
            }
          }
          fValue = Interpreter.castToBool(buf)
          if (opcodenum === Opcode.OP_NOTIF) {
            fValue = !fValue
          }
          this.stack.pop() as Buffer
        }
        this.vfExec.push(fValue)
        break

      case Opcode.OP_ELSE:
        if (this.vfExec.length === 0) {
          this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
          return false
        }
        this.vfExec[this.vfExec.length - 1] = !this.vfExec[this.vfExec.length - 1]
        break

      case Opcode.OP_ENDIF:
        if (this.vfExec.length === 0) {
          this.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
          return false
        }
        this.vfExec.pop()
        break

      case Opcode.OP_VERIFY:
        // (true -- ) or
        // (false -- false) and return
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf = stacktop(-1)
        fValue = Interpreter.castToBool(buf)
        if (fValue) {
          this.stack.pop() as Buffer
        } else {
          this.errstr = 'SCRIPT_ERR_VERIFY'
          return false
        }
        break

      case Opcode.OP_RETURN:
        this.errstr = 'SCRIPT_ERR_OP_RETURN'
        return false
        // break // unreachable

        //
        // Stack ops
        //
      case Opcode.OP_TOALTSTACK:
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.altstack.push(this.stack.pop() as Buffer)
        break

      case Opcode.OP_FROMALTSTACK:
        if (this.altstack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_ALTSTACK_OPERATION'
          return false
        }
        this.stack.push(this.altstack.pop() as Buffer)
        break

      case Opcode.OP_2DROP:
        // (x1 x2 -- )
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.stack.pop() as Buffer
        this.stack.pop() as Buffer
        break

      case Opcode.OP_2DUP:
        // (x1 x2 -- x1 x2 x1 x2)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-2)
        buf2 = stacktop(-1)
        this.stack.push(Buffer.from(buf1))
        this.stack.push(Buffer.from(buf2))
        break

      case Opcode.OP_3DUP:
        // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
        if (this.stack.length < 3) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-3)
        buf2 = stacktop(-2)
        var buf3 = stacktop(-1)
        this.stack.push(Buffer.from(buf1))
        this.stack.push(Buffer.from(buf2))
        this.stack.push(Buffer.from(buf3))
        break

      case Opcode.OP_2OVER:
        // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
        if (this.stack.length < 4) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-4)
        buf2 = stacktop(-3)
        this.stack.push(Buffer.from(buf1))
        this.stack.push(Buffer.from(buf2))
        break

      case Opcode.OP_2ROT:
        // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
        if (this.stack.length < 6) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        spliced = this.stack.splice(this.stack.length - 6, 2)
        this.stack.push(spliced[0])
        this.stack.push(spliced[1])
        break

      case Opcode.OP_2SWAP:
        // (x1 x2 x3 x4 -- x3 x4 x1 x2)
        if (this.stack.length < 4) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        spliced = this.stack.splice(this.stack.length - 4, 2)
        this.stack.push(spliced[0])
        this.stack.push(spliced[1])
        break

      case Opcode.OP_IFDUP:
        // (x - 0 | x x)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf = stacktop(-1)
        fValue = Interpreter.castToBool(buf)
        if (fValue) {
          this.stack.push(Buffer.from(buf))
        }
        break

      case Opcode.OP_DEPTH:
        // -- stacksize
        buf = new BN(this.stack.length).toScriptNumBuffer()
        this.stack.push(buf)
        break

      case Opcode.OP_DROP:
        // (x -- )
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.stack.pop() as Buffer
        break

      case Opcode.OP_DUP:
        // (x -- x x)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.stack.push(Buffer.from(stacktop(-1)))
        break

      case Opcode.OP_NIP:
        // (x1 x2 -- x2)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.stack.splice(this.stack.length - 2, 1)
        break

      case Opcode.OP_OVER:
        // (x1 x2 -- x1 x2 x1)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.stack.push(Buffer.from(stacktop(-2)))
        break

      case Opcode.OP_PICK:
      case Opcode.OP_ROLL:
        // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
        // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf = stacktop(-1)
        bn = BN.fromScriptNumBuffer(buf, fRequireMinimal)
        n = bn.toNumber()
        this.stack.pop() as Buffer
        if (n < 0 || n >= this.stack.length) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf = stacktop(-n - 1)
        if (opcodenum === Opcode.OP_ROLL) {
          this.stack.splice(this.stack.length - n - 1, 1)
        }
        this.stack.push(Buffer.from(buf))
        break

      case Opcode.OP_ROT:
        // (x1 x2 x3 -- x2 x3 x1)
        //  x2 x1 x3  after first swap
        //  x2 x3 x1  after second swap
        if (this.stack.length < 3) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        x1 = stacktop(-3)
        x2 = stacktop(-2)
        var x3 = stacktop(-1)
        this.stack[this.stack.length - 3] = x2
        this.stack[this.stack.length - 2] = x3
        this.stack[this.stack.length - 1] = x1
        break

      case Opcode.OP_SWAP:
        // (x1 x2 -- x2 x1)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        x1 = stacktop(-2)
        x2 = stacktop(-1)
        this.stack[this.stack.length - 2] = x2
        this.stack[this.stack.length - 1] = x1
        break

      case Opcode.OP_TUCK:
        // (x1 x2 -- x2 x1 x2)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        this.stack.splice(this.stack.length - 2, 0, Buffer.from(stacktop(-1)))
        break

      case Opcode.OP_SIZE:
        // (in -- in size)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        bn = new BN(stacktop(-1).length)
        this.stack.push(bn.toScriptNumBuffer())
        break

      //
      // Bitwise logic
      //
      case Opcode.OP_AND:
      case Opcode.OP_OR:
      case Opcode.OP_XOR:
        // (x1 x2 - out)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-2)
        buf2 = stacktop(-1)

        // Inputs must be the same size
        if (buf1.length !== buf2.length) {
          this.errstr = 'SCRIPT_ERR_INVALID_OPERAND_SIZE'
          return false
        }

        // To avoid allocating, we modify vch1 in place.
        switch (opcodenum) {
          case Opcode.OP_AND:
            for (let i = 0; i < buf1.length; i++) {
              buf1[i] = (buf1[i] as number) & (buf2[i] as number)
            }
            break
          case Opcode.OP_OR:
            for (let i = 0; i < buf1.length; i++) {
              buf1[i] = (buf1[i] as number) | (buf2[i] as number)
            }
            break
          case Opcode.OP_XOR:
            for (let i = 0; i < buf1.length; i++) {
              buf1[i] = (buf1[i] as number) ^ (buf2[i] as number)
            }
            break
          default:
            break
        }

        // And pop vch2.
        this.stack.pop() as Buffer
        break

      case Opcode.OP_INVERT:
        // (x -- out)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
        }
        buf = stacktop(-1)
        for (let i = 0; i < buf.length; i++) {
          buf[i] = ~(buf[i] as number)
        }
        break

      case Opcode.OP_LSHIFT:
      case Opcode.OP_RSHIFT:
        // (x n -- out)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-2)
        if (buf1.length === 0) {
          this.stack.pop() as Buffer
        } else {
          bn1 = new BN(buf1)
          bn2 = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal)
          n = bn2.toNumber()
          if (n < 0) {
            this.errstr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE'
            return false
          }
          this.stack.pop() as Buffer
          this.stack.pop() as Buffer
          let shifted
          if (opcodenum === Opcode.OP_LSHIFT) {
            shifted = bn1.ushln(n)
          }
          if (opcodenum === Opcode.OP_RSHIFT) {
            shifted = bn1.ushrn(n)
          }
          // bitcoin client implementation of l/rshift is unconventional, therefore this implementation is a bit unconventional
          // bn library has shift functions however it expands the carried bits into a new byte
          // in contrast to the bitcoin client implementation which drops off the carried bits
          // in other words, if operand was 1 byte then we put 1 byte back on the stack instead of expanding to more shifted bytes
          const bufShifted = padBufferToSize(Buffer.from(shifted.toArray().slice(buf1.length * -1)), buf1.length)
          this.stack.push(bufShifted)
        }
        break

      case Opcode.OP_EQUAL:
      case Opcode.OP_EQUALVERIFY:
        // case Opcode.OP_NOTEQUAL: // use Opcode.OP_NUMNOTEQUAL
        // (x1 x2 - bool)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-2)
        buf2 = stacktop(-1)
        var fEqual = buf1.toString('hex') === buf2.toString('hex')
        this.stack.pop() as Buffer
        this.stack.pop() as Buffer
        this.stack.push(fEqual ? Interpreter.true : Interpreter.false)
        if (opcodenum === Opcode.OP_EQUALVERIFY) {
          if (fEqual) {
            this.stack.pop() as Buffer
          } else {
            this.errstr = 'SCRIPT_ERR_EQUALVERIFY'
            return false
          }
        }
        break

        //
        // Numeric
        //
      case Opcode.OP_2MUL:
      case Opcode.OP_2DIV:
      case Opcode.OP_1ADD:
      case Opcode.OP_1SUB:
      case Opcode.OP_NEGATE:
      case Opcode.OP_ABS:
      case Opcode.OP_NOT:
      case Opcode.OP_0NOTEQUAL:
        // (in -- out)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf = stacktop(-1)
        bn = BN.fromScriptNumBuffer(buf, fRequireMinimal)
        switch (opcodenum) {
          case Opcode.OP_2MUL:
            bn = bn.mul(new BN(2))
            break
          case Opcode.OP_2DIV:
            // Truncates toward zero: -5 OP_2DIV is -2, not -3. Matches the
            // existing OP_DIV, which is `bn1.div(bn2)` on the same BN type, so
            // `x OP_2DIV` and `x 2 OP_DIV` agree. bn.js `shrn` is not usable
            // here — it asserts on negative values.
            bn = bn.div(new BN(2))
            break
          case Opcode.OP_1ADD:
            bn = bn.add(BN.One)
            break
          case Opcode.OP_1SUB:
            bn = bn.sub(BN.One)
            break
          case Opcode.OP_NEGATE:
            bn = bn.neg()
            break
          case Opcode.OP_ABS:
            if (bn.cmp(BN.Zero) < 0) {
              bn = bn.neg()
            }
            break
          case Opcode.OP_NOT:
            bn = new BN(bn.cmp(BN.Zero) === 0 ? 1 : 0)
            break
          case Opcode.OP_0NOTEQUAL:
            bn = new BN(bn.cmp(BN.Zero) !== 0 ? 1 : 0)
            break
            // default:      assert(!'invalid opcode'); break; // TODO: does this ever occur?
        }
        this.stack.pop() as Buffer
        this.stack.push(bn.toScriptNumBuffer())
        break

      case Opcode.OP_ADD:
      case Opcode.OP_SUB:
      case Opcode.OP_MUL:
      case Opcode.OP_MOD:
      case Opcode.OP_DIV:
      case Opcode.OP_BOOLAND:
      case Opcode.OP_BOOLOR:
      case Opcode.OP_NUMEQUAL:
      case Opcode.OP_NUMEQUALVERIFY:
      case Opcode.OP_NUMNOTEQUAL:
      case Opcode.OP_LESSTHAN:
      case Opcode.OP_GREATERTHAN:
      case Opcode.OP_LESSTHANOREQUAL:
      case Opcode.OP_GREATERTHANOREQUAL:
      case Opcode.OP_MIN:
      case Opcode.OP_MAX:
        // (x1 x2 -- out)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        bn1 = BN.fromScriptNumBuffer(stacktop(-2), fRequireMinimal, Interpreter.MAXIMUM_ELEMENT_SIZE)
        bn2 = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal, Interpreter.MAXIMUM_ELEMENT_SIZE)
        bn = new BN(0)

        switch (opcodenum) {
          case Opcode.OP_ADD:
            bn = bn1.add(bn2)
            break

          case Opcode.OP_SUB:
            bn = bn1.sub(bn2)
            break

          case Opcode.OP_MUL:
            bn = bn1.mul(bn2)
            break

          case Opcode.OP_DIV:
            // denominator must not be 0
            if (bn2 === 0) {
              this.errstr = 'SCRIPT_ERR_DIV_BY_ZERO'
              return false
            }
            bn = bn1.div(bn2)
            break

          case Opcode.OP_MOD:
            // divisor must not be 0
            if (bn2 === 0) {
              this.errstr = 'SCRIPT_ERR_DIV_BY_ZERO'
              return false
            }
            bn = bn1.mod(bn2)
            break

          case Opcode.OP_BOOLAND:
            bn = new BN(((bn1.cmp(BN.Zero) !== 0) && (bn2.cmp(BN.Zero) !== 0)) ? 1 : 0)
            break
            // case Opcode.OP_BOOLOR:        bn = (bn1 !== bnZero || bn2 !== bnZero); break;
          case Opcode.OP_BOOLOR:
            bn = new BN(((bn1.cmp(BN.Zero) !== 0) || (bn2.cmp(BN.Zero) !== 0)) ? 1 : 0)
            break
            // case Opcode.OP_NUMEQUAL:      bn = (bn1 === bn2); break;
          case Opcode.OP_NUMEQUAL:
            bn = new BN(bn1.cmp(bn2) === 0 ? 1 : 0)
            break
            // case Opcode.OP_NUMEQUALVERIFY:    bn = (bn1 === bn2); break;
          case Opcode.OP_NUMEQUALVERIFY:
            bn = new BN(bn1.cmp(bn2) === 0 ? 1 : 0)
            break
            // case Opcode.OP_NUMNOTEQUAL:     bn = (bn1 !== bn2); break;
          case Opcode.OP_NUMNOTEQUAL:
            bn = new BN(bn1.cmp(bn2) !== 0 ? 1 : 0)
            break
            // case Opcode.OP_LESSTHAN:      bn = (bn1 < bn2); break;
          case Opcode.OP_LESSTHAN:
            bn = new BN(bn1.cmp(bn2) < 0 ? 1 : 0)
            break
            // case Opcode.OP_GREATERTHAN:     bn = (bn1 > bn2); break;
          case Opcode.OP_GREATERTHAN:
            bn = new BN(bn1.cmp(bn2) > 0 ? 1 : 0)
            break
            // case Opcode.OP_LESSTHANOREQUAL:   bn = (bn1 <= bn2); break;
          case Opcode.OP_LESSTHANOREQUAL:
            bn = new BN(bn1.cmp(bn2) <= 0 ? 1 : 0)
            break
            // case Opcode.OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
          case Opcode.OP_GREATERTHANOREQUAL:
            bn = new BN(bn1.cmp(bn2) >= 0 ? 1 : 0)
            break
          case Opcode.OP_MIN:
            bn = (bn1.cmp(bn2) < 0 ? bn1 : bn2)
            break
          case Opcode.OP_MAX:
            bn = (bn1.cmp(bn2) > 0 ? bn1 : bn2)
            break
            // default:           assert(!'invalid opcode'); break; //TODO: does this ever occur?
        }
        this.stack.pop() as Buffer
        this.stack.pop() as Buffer
        this.stack.push(bn.toScriptNumBuffer())

        if (opcodenum === Opcode.OP_NUMEQUALVERIFY) {
          // if (CastToBool(stacktop(-1)))
          if (Interpreter.castToBool(stacktop(-1))) {
            this.stack.pop() as Buffer
          } else {
            this.errstr = 'SCRIPT_ERR_NUMEQUALVERIFY'
            return false
          }
        }
        break

      case Opcode.OP_WITHIN:
        // (x min max -- out)
        if (this.stack.length < 3) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        bn1 = BN.fromScriptNumBuffer(stacktop(-3), fRequireMinimal, Interpreter.MAXIMUM_ELEMENT_SIZE)
        bn2 = BN.fromScriptNumBuffer(stacktop(-2), fRequireMinimal, Interpreter.MAXIMUM_ELEMENT_SIZE)
        var bn3 = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal, Interpreter.MAXIMUM_ELEMENT_SIZE)
        // bool fValue = (bn2 <= bn1 && bn1 < bn3);
        fValue = (bn2.cmp(bn1) <= 0) && (bn1.cmp(bn3) < 0)
        this.stack.pop() as Buffer
        this.stack.pop() as Buffer
        this.stack.pop() as Buffer
        this.stack.push(fValue ? Interpreter.true : Interpreter.false)
        break

        //
        // Crypto
        //
      case Opcode.OP_RIPEMD160:
      case Opcode.OP_SHA1:
      case Opcode.OP_SHA256:
      case Opcode.OP_HASH160:
      case Opcode.OP_HASH256:
        // (in -- hash)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf = stacktop(-1)
        // valtype vchHash((opcode === Opcode.OP_RIPEMD160 ||
        //                 opcode === Opcode.OP_SHA1 || opcode === Opcode.OP_HASH160) ? 20 : 32);
        var bufHash
        if (opcodenum === Opcode.OP_RIPEMD160) {
          bufHash = Hash.ripemd160(buf)
        } else if (opcodenum === Opcode.OP_SHA1) {
          bufHash = Hash.sha1(buf)
        } else if (opcodenum === Opcode.OP_SHA256) {
          bufHash = Hash.sha256(buf)
        } else if (opcodenum === Opcode.OP_HASH160) {
          bufHash = Hash.sha256ripemd160(buf)
        } else if (opcodenum === Opcode.OP_HASH256) {
          bufHash = Hash.sha256sha256(buf)
        }
        this.stack.pop() as Buffer
        this.stack.push(bufHash as Buffer)
        break

      case Opcode.OP_CODESEPARATOR:
        // Hash starts after the code separator
        this.pbegincodehash = this.pc
        break

      case Opcode.OP_CHECKSIG:
      case Opcode.OP_CHECKSIGVERIFY:
        // (sig pubkey -- bool)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        bufSig = stacktop(-2)
        bufPubkey = stacktop(-1)

        if (!this.checkSignatureEncoding(bufSig) || !this.checkPubkeyEncoding(bufPubkey)) {
          return false
        }

        // Subset of script starting at the most recent codeseparator
        // CScript scriptCode(pbegincodehash, pend);
        subscript = new Script().set({
          chunks: this.script!.chunks.slice(this.pbegincodehash)
        })

        // Drop the signature, since there's no way for a signature to sign itself
        var tmpScript = new Script().add(bufSig)
        subscript.findAndDelete(tmpScript)

        try {
          sig = Signature.fromTxFormat(bufSig)
          pubkey = publicKeyClass().fromBuffer(bufPubkey, false)

          fSuccess = this.tx!.verifySignature(sig, pubkey, this.nin!, subscript, this.satoshisBN, this.flags)
        } catch (e) {
          // invalid sig or pubkey
          fSuccess = false
        }

        if (!fSuccess && (this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL) &&
          bufSig.length) {
          this.errstr = 'SCRIPT_ERR_NULLFAIL'
          return false
        }

        this.stack.pop() as Buffer
        this.stack.pop() as Buffer

        // stack.push_back(fSuccess ? vchTrue : vchFalse);
        this.stack.push(fSuccess ? Interpreter.true : Interpreter.false)
        if (opcodenum === Opcode.OP_CHECKSIGVERIFY) {
          if (fSuccess) {
            this.stack.pop() as Buffer
          } else {
            this.errstr = 'SCRIPT_ERR_CHECKSIGVERIFY'
            return false
          }
        }
        break

      case Opcode.OP_CHECKMULTISIG:
      case Opcode.OP_CHECKMULTISIGVERIFY:
        // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

        var i = 1
        if (this.stack.length < i) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        var nKeysCount = BN.fromScriptNumBuffer(stacktop(-i), fRequireMinimal).toNumber()
        // TODO: Keys and opcount are parameterized in client. No magic numbers!
        if (nKeysCount < 0 || nKeysCount > 20) {
          this.errstr = 'SCRIPT_ERR_PUBKEY_COUNT'
          return false
        }
        this.nOpCount += nKeysCount
        if (this.nOpCount > Interpreter.MAX_OPS_PER_SCRIPT) {
          this.errstr = 'SCRIPT_ERR_OP_COUNT'
          return false
        }
        // int ikey = ++i;
        var ikey = ++i
        i += nKeysCount

        // ikey2 is the position of last non-signature item in
        // the stack. Top stack item = 1. With
        // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
        // operation fails.
        var ikey2 = nKeysCount + 2

        if (this.stack.length < i) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        var nSigsCount = BN.fromScriptNumBuffer(stacktop(-i), fRequireMinimal).toNumber()
        if (nSigsCount < 0 || nSigsCount > nKeysCount) {
          this.errstr = 'SCRIPT_ERR_SIG_COUNT'
          return false
        }
        // int isig = ++i;
        var isig = ++i
        i += nSigsCount
        if (this.stack.length < i) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        // Subset of script starting at the most recent codeseparator
        subscript = new Script().set({
          chunks: this.script!.chunks.slice(this.pbegincodehash)
        })

        // Drop the signatures, since there's no way for a signature to sign itself
        for (let k = 0; k < nSigsCount; k++) {
          bufSig = stacktop(-isig - k)
          subscript.findAndDelete(new Script().add(bufSig))
        }

        fSuccess = true
        while (fSuccess && nSigsCount > 0) {
          // valtype& vchSig  = stacktop(-isig);
          bufSig = stacktop(-isig)
          // valtype& vchPubKey = stacktop(-ikey);
          bufPubkey = stacktop(-ikey)

          if (!this.checkSignatureEncoding(bufSig) || !this.checkPubkeyEncoding(bufPubkey)) {
            return false
          }

          var fOk
          try {
            sig = Signature.fromTxFormat(bufSig)
            pubkey = publicKeyClass().fromBuffer(bufPubkey, false)
            fOk = this.tx!.verifySignature(sig, pubkey, this.nin!, subscript, this.satoshisBN, this.flags)
          } catch (e) {
            // invalid sig or pubkey
            fOk = false
          }

          if (fOk) {
            isig++
            nSigsCount--
          }
          ikey++
          nKeysCount--

          // If there are more signatures left than keys left,
          // then too many signatures have failed
          if (nSigsCount > nKeysCount) {
            fSuccess = false
          }
        }

        // Clean up stack of actual arguments
        while (i-- > 1) {
          if (!fSuccess && (this.flags & Interpreter.SCRIPT_VERIFY_NULLFAIL) &&
            !ikey2 && stacktop(-1).length) {
            this.errstr = 'SCRIPT_ERR_NULLFAIL'
            return false
          }

          if (ikey2 > 0) {
            ikey2--
          }

          this.stack.pop() as Buffer
        }

        // A bug causes CHECKMULTISIG to consume one extra argument
        // whose contents were not checked in any way.
        //
        // Unfortunately this is a potential source of mutability,
        // so optionally verify it is exactly equal to zero prior
        // to removing it from the stack.
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        if ((this.flags & Interpreter.SCRIPT_VERIFY_NULLDUMMY) && stacktop(-1).length) {
          this.errstr = 'SCRIPT_ERR_SIG_NULLDUMMY'
          return false
        }
        this.stack.pop() as Buffer

        this.stack.push(fSuccess ? Interpreter.true : Interpreter.false)

        if (opcodenum === Opcode.OP_CHECKMULTISIGVERIFY) {
          if (fSuccess) {
            this.stack.pop() as Buffer
          } else {
            this.errstr = 'SCRIPT_ERR_CHECKMULTISIGVERIFY'
            return false
          }
        }
        break

        //
        // Byte string operations
        //
      case Opcode.OP_CAT:
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        buf1 = stacktop(-2)
        buf2 = stacktop(-1)
        if (buf1.length + buf2.length > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
          this.errstr = 'SCRIPT_ERR_PUSH_SIZE'
          return false
        }
        this.stack[this.stack.length - 2] = Buffer.concat([buf1, buf2])
        this.stack.pop() as Buffer
        break

      case Opcode.OP_SPLIT:
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-2)

        // Make sure the split point is apropriate.
        var position = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal).toNumber()
        if (position < 0 || position > buf1.length) {
          this.errstr = 'SCRIPT_ERR_INVALID_SPLIT_RANGE'
          return false
        }

        // Prepare the results in their own buffer as `data`
        // will be invalidated.
        // Copy buffer data, to slice it before
        var n1 = Buffer.from(buf1)

        // Replace existing stack values by the new values.
        this.stack[this.stack.length - 2] = n1.slice(0, position)
        this.stack[this.stack.length - 1] = n1.slice(position)
        break

      case Opcode.OP_LEFT:
      case Opcode.OP_RIGHT:
        // (in size -- out)  OP_LEFT keeps the first `size` bytes; OP_RIGHT the last.
        // Re-enabled string opcodes (BSV Chronicle). Original Satoshi semantics.
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-2)
        n = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal).toNumber()
        if (n < 0) {
          this.errstr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE'
          return false
        }
        if (n > buf1.length) {
          n = buf1.length
        }
        this.stack.pop() as Buffer
        if (opcodenum === Opcode.OP_LEFT) {
          this.stack[this.stack.length - 1] = Buffer.from(buf1).slice(0, n)
        } else {
          this.stack[this.stack.length - 1] = Buffer.from(buf1).slice(buf1.length - n)
        }
        break

      case Opcode.OP_SUBSTR:
        // (in begin size -- out)  out = in[begin : begin + size]
        // Re-enabled string opcode (BSV Chronicle). Original Satoshi semantics.
        if (this.stack.length < 3) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }
        buf1 = stacktop(-3)
        var subSize = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal).toNumber()
        var subBegin = BN.fromScriptNumBuffer(stacktop(-2), fRequireMinimal).toNumber()
        if (subBegin < 0 || subSize < 0) {
          this.errstr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE'
          return false
        }
        if (subBegin > buf1.length) {
          subBegin = buf1.length
        }
        if (subBegin + subSize > buf1.length) {
          subSize = buf1.length - subBegin
        }
        this.stack.pop() as Buffer
        this.stack.pop() as Buffer
        this.stack[this.stack.length - 1] = Buffer.from(buf1).slice(subBegin, subBegin + subSize)
        break

        //
        // Conversion operations
        //
      case Opcode.OP_NUM2BIN:
        // (in -- out)
        if (this.stack.length < 2) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        var size = BN.fromScriptNumBuffer(stacktop(-1), fRequireMinimal).toNumber()
        if (size > Interpreter.MAX_SCRIPT_ELEMENT_SIZE) {
          this.errstr = 'SCRIPT_ERR_PUSH_SIZE'
          return false
        }

        this.stack.pop() as Buffer
        var rawnum = stacktop(-1)

        // Try to see if we can fit that number in the number of
        // byte requested.
        rawnum = Interpreter._minimallyEncode(rawnum)

        if (rawnum.length > size) {
          // We definitively cannot.
          this.errstr = 'SCRIPT_ERR_IMPOSSIBLE_ENCODING'
          return false
        }

        // We already have an element of the right size, we
        // don't need to do anything.
        if (rawnum.length === size) {
          this.stack[this.stack.length - 1] = rawnum
          break
        }

        var signbit = 0x00
        if (rawnum.length > 0) {
          // Guarded by `rawnum.length > 0` immediately above.
          signbit = (rawnum[rawnum.length - 1] as number) & 0x80
          rawnum[rawnum.length - 1] = (rawnum[rawnum.length - 1] as number) & 0x7f
        }

        var num = Buffer.alloc(size)
        rawnum.copy(num, 0)

        var l = rawnum.length - 1
        while (l++ < size - 2) {
          num[l] = 0x00
        }

        num[l] = signbit

        this.stack[this.stack.length - 1] = num
        break

      case Opcode.OP_BIN2NUM:
        // (in -- out)
        if (this.stack.length < 1) {
          this.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
          return false
        }

        buf1 = stacktop(-1)
        buf2 = Interpreter._minimallyEncode(buf1)

        this.stack[this.stack.length - 1] = buf2

        // The resulting number must be a valid number.
        if (!Interpreter._isMinimallyEncoded(buf2)) {
          this.errstr = 'SCRIPT_ERR_INVALID_NUMBER_RANGE'
          return false
        }
        break

      default:
        this.errstr = 'SCRIPT_ERR_BAD_OPCODE'
        return false
    }
  }

  return true
}
