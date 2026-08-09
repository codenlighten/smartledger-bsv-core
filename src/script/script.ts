'use strict'

import BufferReader = require('../encoding/bufferreader')
import BufferWriter = require('../encoding/bufferwriter')
import Hash = require('../crypto/hash')
import Opcode = require('../opcode')
import Signature = require('../crypto/signature')
import Networks = require('../networks')
import $ = require('../util/preconditions')
import _ = require('../util/_')
import errors = require('../errors')
import JSUtil = require('../util/js')
import type { Script, ScriptConstructor, ScriptChunk, ScriptAddressInfo, ScriptAddable, AddressLike, PublicKeyLike, NetworkLike, MultisigOpts } from './script.types'
import type { PublicKey } from '../publickey.types'
import type { Address } from '../address.types'

// address and publickey are in this cycle, so both resolve on demand.
const addressClass = (): any => require('../address')
const publicKeyClass = (): any => require('../publickey')

// The error tree is built dynamically; its members arrive via an index
// signature, so they are narrowed once here.
type ErrCtor = new (...args: unknown[]) => Error
const scriptErr = (name: string): ErrCtor =>
  (errors.Script as Record<string, unknown>)[name] as ErrCtor

// NOTE ON THE `as ScriptChunk` CASTS BELOW: the classification predicates read
// `chunks.length === N && chunks[0]... && chunks[N-1]...`. The length check
// guards every index, but TypeScript will not carry it through `&&` into a
// later operand, so noUncheckedIndexedAccess flags each read. The casts are
// erased, so a short chunk list still short-circuits on the length check and
// never reaches the index.

/**
 * A bitcoin transaction script. Each transaction's inputs and outputs
 * has a script that is evaluated to validate it's spending.
 *
 * See https://en.bitcoin.it/wiki/Script
 *
 * @constructor
 * @param {Object|string|Buffer=} from optional data to populate script
 */
const Script = function Script (this: Script, from?: unknown) {
  if (!(this instanceof Script)) {
    return new (Script as unknown as ScriptConstructor)(from)
  }
  this.chunks = []

  if (Buffer.isBuffer(from)) {
    return (Script as unknown as ScriptConstructor).fromBuffer(from)
  } else if (from instanceof (addressClass() as new () => unknown)) {
    return (Script as unknown as ScriptConstructor).fromAddress(from as AddressLike)
  } else if (from instanceof (Script as unknown as new () => unknown)) {
    return (Script as unknown as ScriptConstructor).fromBuffer((from as Script).toBuffer())
  } else if (_.isString(from)) {
    return (Script as unknown as ScriptConstructor).fromString(from)
  } else if (_.isObject(from) && _.isArray((from as { chunks?: unknown }).chunks)) {
    this.set(from as { chunks: ScriptChunk[] })
  }
} as unknown as ScriptConstructor

Script.prototype.set = function (this: Script, obj: { chunks: ScriptChunk[] }) {
  $.checkArgument(_.isObject(obj))
  $.checkArgument(_.isArray(obj.chunks))
  this.chunks = obj.chunks
  return this
}

Script.fromBuffer = function (buffer: Buffer) {
  const script = new Script()
  script.chunks = []

  const br = new BufferReader(buffer)
  while (!br.finished()) {
    try {
      const opcodenum = br.readUInt8()

      var len, buf
      if (opcodenum > 0 && opcodenum < Opcode.OP_PUSHDATA1) {
        len = opcodenum
        script.chunks.push({
          buf: br.read(len),
          len,
          opcodenum
        })
      } else if (opcodenum === Opcode.OP_PUSHDATA1) {
        len = br.readUInt8()
        buf = br.read(len)
        script.chunks.push({
          buf,
          len,
          opcodenum
        })
      } else if (opcodenum === Opcode.OP_PUSHDATA2) {
        len = br.readUInt16LE()
        buf = br.read(len)
        script.chunks.push({
          buf,
          len,
          opcodenum
        })
      } else if (opcodenum === Opcode.OP_PUSHDATA4) {
        len = br.readUInt32LE()
        buf = br.read(len)
        script.chunks.push({
          buf,
          len,
          opcodenum
        })
      } else {
        script.chunks.push({
          opcodenum
        })
      }
    } catch (e) {
      if (e instanceof RangeError) {
        throw new (scriptErr('InvalidBuffer'))(buffer.toString('hex'))
      }
      throw e
    }
  }

  return script
}

Script.prototype.toBuffer = function (this: Script) {
  const bw = new BufferWriter()

  for (let i = 0; i < this.chunks.length; i++) {
    const chunk = this.chunks[i] as ScriptChunk
    const opcodenum = chunk.opcodenum
    bw.writeUInt8(chunk.opcodenum)
    if (chunk.buf) {
      if (opcodenum < Opcode.OP_PUSHDATA1) {
        bw.write(chunk.buf)
      } else if (opcodenum === Opcode.OP_PUSHDATA1) {
        bw.writeUInt8(chunk.len as number)
        bw.write(chunk.buf)
      } else if (opcodenum === Opcode.OP_PUSHDATA2) {
        bw.writeUInt16LE(chunk.len as number)
        bw.write(chunk.buf)
      } else if (opcodenum === Opcode.OP_PUSHDATA4) {
        bw.writeUInt32LE(chunk.len as number)
        bw.write(chunk.buf)
      }
    }
  }

  return bw.concat()
}

Script.fromASM = function (str: string) {
  const script = new Script()
  script.chunks = []

  const tokens = str.split(' ')
  let i = 0
  while (i < tokens.length) {
    const token = tokens[i]
    const opcode = Opcode(token!)
    let opcodenum = opcode.toNumber()

    // we start with two special cases, 0 and -1, which are handled specially in
    // toASM. see _chunkToString.
    if (token === '0') {
      opcodenum = 0
      script.chunks.push({
        opcodenum
      })
      i = i + 1
    } else if (token === '-1') {
      opcodenum = Opcode.OP_1NEGATE
      script.chunks.push({
        opcodenum
      })
      i = i + 1
    } else if (_.isUndefined(opcodenum)) {
      const buf = Buffer.from(tokens[i]!, 'hex')
      if (buf.toString('hex') !== tokens[i]!) {
        throw new Error('invalid hex string in script')
      }
      const len = buf.length
      if (len >= 0 && len < Opcode.OP_PUSHDATA1) {
        opcodenum = len
      } else if (len < Math.pow(2, 8)) {
        opcodenum = Opcode.OP_PUSHDATA1
      } else if (len < Math.pow(2, 16)) {
        opcodenum = Opcode.OP_PUSHDATA2
      } else if (len < Math.pow(2, 32)) {
        opcodenum = Opcode.OP_PUSHDATA4
      }
      script.chunks.push({
        buf,
        len: buf.length,
        opcodenum
      })
      i = i + 1
    } else {
      script.chunks.push({
        opcodenum
      })
      i = i + 1
    }
  }
  return script
}

Script.fromHex = function (str: string) {
  return new Script(Buffer.from(str, 'hex'))
}

Script.fromString = function (str: string) {
  if (JSUtil.isHexa(str) || str.length === 0) {
    return new Script(Buffer.from(str, 'hex'))
  }
  const script = new Script()
  script.chunks = []

  const tokens = str.split(' ')
  let i = 0
  while (i < tokens.length) {
    const token = tokens[i]
    const opcode = Opcode(token!)
    let opcodenum = opcode.toNumber()

    if (_.isUndefined(opcodenum)) {
      opcodenum = parseInt(token!)
      if (opcodenum > 0 && opcodenum < Opcode.OP_PUSHDATA1) {
        script.chunks.push({
          buf: Buffer.from(tokens[i + 1]!.slice(2), 'hex'),
          len: opcodenum,
          opcodenum
        })
        i = i + 2
      } else {
        throw new Error('Invalid script: ' + JSON.stringify(str))
      }
    } else if (opcodenum === Opcode.OP_PUSHDATA1 ||
      opcodenum === Opcode.OP_PUSHDATA2 ||
      opcodenum === Opcode.OP_PUSHDATA4) {
      if (tokens[i + 2]!.slice(0, 2) !== '0x') {
        throw new Error('Pushdata data must start with 0x')
      }
      script.chunks.push({
        buf: Buffer.from(tokens[i + 2]!.slice(2), 'hex'),
        len: parseInt(tokens[i + 1]!),
        opcodenum
      })
      i = i + 3
    } else {
      script.chunks.push({
        opcodenum
      })
      i = i + 1
    }
  }
  return script
}

Script.prototype._chunkToString = function (this: Script, chunk: ScriptChunk, type?: string) {
  const opcodenum = chunk.opcodenum
  const asm = (type === 'asm')
  let str = ''
  if (!chunk.buf) {
    // no data chunk
    if (typeof Opcode.reverseMap[opcodenum] !== 'undefined') {
      if (asm) {
        // A few cases where the opcode name differs from reverseMap
        // aside from 1 to 16 data pushes.
        if (opcodenum === 0) {
          // OP_0 -> 0
          str = str + ' 0'
        } else if (opcodenum === 79) {
          // OP_1NEGATE -> 1
          str = str + ' -1'
        } else {
          str = str + ' ' + Opcode(opcodenum).toString()
        }
      } else {
        str = str + ' ' + Opcode(opcodenum).toString()
      }
    } else {
      let numstr = opcodenum.toString(16)
      if (numstr.length % 2 !== 0) {
        numstr = '0' + numstr
      }
      if (asm) {
        str = str + ' ' + numstr
      } else {
        str = str + ' ' + '0x' + numstr
      }
    }
  } else {
    // data chunk
    if (!asm && (opcodenum === Opcode.OP_PUSHDATA1 ||
      opcodenum === Opcode.OP_PUSHDATA2 ||
      opcodenum === Opcode.OP_PUSHDATA4)) {
      str = str + ' ' + Opcode(opcodenum).toString()
    }
    if (chunk.len != null && chunk.len > 0) {
      if (asm) {
        str = str + ' ' + chunk.buf.toString('hex')
      } else {
        str = str + ' ' + chunk.len + ' ' + '0x' + chunk.buf.toString('hex')
      }
    }
  }
  return str
}

Script.prototype.toASM = function (this: Script) {
  let str = ''
  for (let i = 0; i < this.chunks.length; i++) {
    const chunk = this.chunks[i] as ScriptChunk
    str += this._chunkToString(chunk, 'asm')
  }

  return str.substr(1)
}

Script.prototype.toString = function (this: Script) {
  let str = ''
  for (let i = 0; i < this.chunks.length; i++) {
    const chunk = this.chunks[i] as ScriptChunk
    str += this._chunkToString(chunk)
  }

  return str.substr(1)
}

Script.prototype.toHex = function (this: Script) {
  return this.toBuffer().toString('hex')
}

Script.prototype.inspect = function (this: Script) {
  return '<Script: ' + this.toString() + '>'
}

// script classification methods

/**
 * @returns {boolean} if this is a pay to pubkey hash output script
 */
Script.prototype.isPublicKeyHashOut = function (this: Script) {
  return !!(this.chunks.length === 5 &&
    (this.chunks[0] as ScriptChunk).opcodenum === Opcode.OP_DUP &&
    (this.chunks[1] as ScriptChunk).opcodenum === Opcode.OP_HASH160 &&
    (this.chunks[2] as ScriptChunk).buf &&
    (this.chunks[2] as ScriptChunk).buf!.length === 20 &&
    (this.chunks[3] as ScriptChunk).opcodenum === Opcode.OP_EQUALVERIFY &&
    (this.chunks[4] as ScriptChunk).opcodenum === Opcode.OP_CHECKSIG)
}

/**
 * @returns {boolean} true if the FIRST five chunks are a P2PKH pattern, regardless
 *   of any trailing chunks. Matches 1Sat Ordinals (P2PKH + `OP_FALSE OP_IF "ord" …
 *   OP_ENDIF`), MAP+BAP-style appended metadata, sCrypt covenants with a P2PKH
 *   spendable guard, etc. The strict `isPublicKeyHashOut()` is unchanged so
 *   address derivation / script classification keep their canonical semantics;
 *   this loose check is used by `Transaction.from()` so spending such outputs
 *   via the high-level API Just Works.
 */
Script.prototype.isPublicKeyHashOutPrefix = function (this: Script) {
  return !!(this.chunks.length >= 5 &&
    (this.chunks[0] as ScriptChunk).opcodenum === Opcode.OP_DUP &&
    (this.chunks[1] as ScriptChunk).opcodenum === Opcode.OP_HASH160 &&
    (this.chunks[2] as ScriptChunk).buf &&
    (this.chunks[2] as ScriptChunk).buf!.length === 20 &&
    (this.chunks[3] as ScriptChunk).opcodenum === Opcode.OP_EQUALVERIFY &&
    (this.chunks[4] as ScriptChunk).opcodenum === Opcode.OP_CHECKSIG)
}

/**
 * @returns {boolean} if this is a pay to public key hash input script
 */
Script.prototype.isPublicKeyHashIn = function (this: Script) {
  if (this.chunks.length === 2) {
    const signatureBuf = (this.chunks[0] as ScriptChunk).buf
    const pubkeyBuf = (this.chunks[1] as ScriptChunk).buf
    if (signatureBuf &&
      signatureBuf.length &&
      signatureBuf[0] === 0x30 &&
      pubkeyBuf &&
      pubkeyBuf.length
    ) {
      const version = pubkeyBuf[0]
      if ((version === 0x04 ||
        version === 0x06 ||
        version === 0x07) && pubkeyBuf.length === 65) {
        return true
      } else if ((version === 0x03 || version === 0x02) && pubkeyBuf.length === 33) {
        return true
      }
    }
  }
  return false
}

Script.prototype.getPublicKey = function (this: Script) {
  $.checkState(this.isPublicKeyOut(), 'Can\'t retrieve PublicKey from a non-PK output')
  return (this.chunks[0] as ScriptChunk).buf
}

Script.prototype.getPublicKeyHash = function (this: Script) {
  $.checkState(this.isPublicKeyHashOut(), 'Can\'t retrieve PublicKeyHash from a non-PKH output')
  return (this.chunks[2] as ScriptChunk).buf
}

/**
 * @returns {boolean} if this is a public key output script
 */
Script.prototype.isPublicKeyOut = function (this: Script) {
  if (this.chunks.length === 2 &&
    (this.chunks[0] as ScriptChunk).buf &&
    (this.chunks[0] as ScriptChunk).buf!.length &&
    (this.chunks[1] as ScriptChunk).opcodenum === Opcode.OP_CHECKSIG) {
    const pubkeyBuf = (this.chunks[0] as ScriptChunk).buf as Buffer
    const version = pubkeyBuf[0]
    let isVersion = false
    if ((version === 0x04 ||
      version === 0x06 ||
      version === 0x07) && pubkeyBuf.length === 65) {
      isVersion = true
    } else if ((version === 0x03 || version === 0x02) && pubkeyBuf.length === 33) {
      isVersion = true
    }
    if (isVersion) {
      return publicKeyClass().isValid(pubkeyBuf)
    }
  }
  return false
}

/**
 * @returns {boolean} if this is a pay to public key input script
 */
Script.prototype.isPublicKeyIn = function (this: Script) {
  if (this.chunks.length === 1) {
    const signatureBuf = (this.chunks[0] as ScriptChunk).buf
    if (signatureBuf &&
      signatureBuf.length &&
      signatureBuf[0] === 0x30) {
      return true
    }
  }
  return false
}

/**
 * @returns {boolean} if this is a p2sh output script
 */
Script.prototype.isScriptHashOut = function (this: Script) {
  const buf = this.toBuffer()
  return (buf.length === 23 &&
    buf[0] === Opcode.OP_HASH160 &&
    buf[1] === 0x14 &&
    buf[buf.length - 1] === Opcode.OP_EQUAL)
}

/**
 * @returns {boolean} if this is a p2sh input script
 * Note that these are frequently indistinguishable from pubkeyhashin
 */
Script.prototype.isScriptHashIn = function (this: Script) {
  if (this.chunks.length <= 1) {
    return false
  }
  const redeemChunk = this.chunks[this.chunks.length - 1] as ScriptChunk
  const redeemBuf = redeemChunk.buf
  if (!redeemBuf) {
    return false
  }

  let redeemScript
  try {
    redeemScript = Script.fromBuffer(redeemBuf)
  } catch (e) {
    if (e instanceof scriptErr('InvalidBuffer')) {
      return false
    }
    throw e
  }
  const type = redeemScript.classify()
  return type !== Script.types.UNKNOWN
}

/**
 * @returns {boolean} if this is a mutlsig output script
 */
Script.prototype.isMultisigOut = function (this: Script) {
  return (this.chunks.length > 3 &&
    Opcode.isSmallIntOp((this.chunks[0] as ScriptChunk).opcodenum) &&
    this.chunks.slice(1, this.chunks.length - 2).every(function (obj) {
      return obj.buf && Buffer.isBuffer(obj.buf)
    }) &&
    Opcode.isSmallIntOp((this.chunks[this.chunks.length - 2] as ScriptChunk).opcodenum) &&
    (this.chunks[this.chunks.length - 1] as ScriptChunk).opcodenum === Opcode.OP_CHECKMULTISIG)
}

/**
 * @returns {boolean} if this is a multisig input script
 */
Script.prototype.isMultisigIn = function (this: Script) {
  return this.chunks.length >= 2 &&
    (this.chunks[0] as ScriptChunk).opcodenum === 0 &&
    this.chunks.slice(1, this.chunks.length).every(function (obj) {
      return obj.buf &&
        Buffer.isBuffer(obj.buf) &&
        Signature.isTxDER(obj.buf)
    })
}

/**
 * @returns {boolean} true if this is a valid standard OP_RETURN output
 */
Script.prototype.isDataOut = function (this: Script) {
  const step1 = this.chunks.length >= 1 &&
    (this.chunks[0] as ScriptChunk).opcodenum === Opcode.OP_RETURN
  if (!step1) return false
  const chunks = this.chunks.slice(1)
  const script2 = new Script({ chunks })
  return script2.isPushOnly()
}

Script.prototype.isSafeDataOut = function (this: Script) {
  if (this.chunks.length < 2) {
    return false
  }
  if ((this.chunks[0] as ScriptChunk).opcodenum !== Opcode.OP_FALSE) {
    return false
  }
  const chunks = this.chunks.slice(1)
  const script2 = new Script({ chunks })
  return script2.isDataOut()
}

/**
 * Retrieve the associated data for this script.
 * In the case of a pay to public key hash or P2SH, return the hash.
 * In the case of safe OP_RETURN data, return an array of buffers
 * In the case of a standard deprecated OP_RETURN, return the data
 * @returns {Buffer}
 */
Script.prototype.getData = function (this: Script) {
  if (this.isSafeDataOut()) {
    const chunks = this.chunks.slice(2)
    const buffers = chunks.map(chunk => chunk.buf)
    return buffers
  }
  if (this.isDataOut() || this.isScriptHashOut()) {
    if (_.isUndefined(this.chunks[1])) {
      return Buffer.alloc(0)
    } else {
      return Buffer.from((this.chunks[1] as ScriptChunk).buf as Buffer)
    }
  }
  if (this.isPublicKeyHashOut()) {
    return Buffer.from((this.chunks[2] as ScriptChunk).buf as Buffer)
  }
  throw new Error('Unrecognized script type to get data from')
}

/**
 * @returns {boolean} if the script is only composed of data pushing
 * opcodes or small int opcodes (OP_0, OP_1, ..., OP_16)
 */
Script.prototype.isPushOnly = function (this: Script) {
  return _.every(this.chunks, function (chunk) {
    return chunk.opcodenum <= Opcode.OP_16 ||
      chunk.opcodenum === Opcode.OP_PUSHDATA1 ||
      chunk.opcodenum === Opcode.OP_PUSHDATA2 ||
      chunk.opcodenum === Opcode.OP_PUSHDATA4
  })
}

Script.types = {}
Script.types.UNKNOWN = 'Unknown'
Script.types.PUBKEY_OUT = 'Pay to public key'
Script.types.PUBKEY_IN = 'Spend from public key'
Script.types.PUBKEYHASH_OUT = 'Pay to public key hash'
Script.types.PUBKEYHASH_IN = 'Spend from public key hash'
Script.types.SCRIPTHASH_OUT = 'Pay to script hash'
Script.types.SCRIPTHASH_IN = 'Spend from script hash'
Script.types.MULTISIG_OUT = 'Pay to multisig'
Script.types.MULTISIG_IN = 'Spend from multisig'
Script.types.DATA_OUT = 'Data push'
Script.types.SAFE_DATA_OUT = 'Safe data push'

Script.OP_RETURN_STANDARD_SIZE = 220

/**
 * @returns {object} The Script type if it is a known form,
 * or Script.UNKNOWN if it isn't
 */
Script.prototype.classify = function (this: Script) {
  if (this._isInput) {
    return this.classifyInput()
  } else if (this._isOutput) {
    return this.classifyOutput()
  } else {
    const outputType = this.classifyOutput()
    return outputType !== Script.types.UNKNOWN ? outputType : this.classifyInput()
  }
}

Script.outputIdentifiers = {}
Script.outputIdentifiers.PUBKEY_OUT = Script.prototype.isPublicKeyOut
Script.outputIdentifiers.PUBKEYHASH_OUT = Script.prototype.isPublicKeyHashOut
Script.outputIdentifiers.MULTISIG_OUT = Script.prototype.isMultisigOut
Script.outputIdentifiers.SCRIPTHASH_OUT = Script.prototype.isScriptHashOut
Script.outputIdentifiers.DATA_OUT = Script.prototype.isDataOut
Script.outputIdentifiers.SAFE_DATA_OUT = Script.prototype.isSafeDataOut

/**
 * @returns {object} The Script type if it is a known form,
 * or Script.UNKNOWN if it isn't
 */
Script.prototype.classifyOutput = function (this: Script) {
  for (const type in Script.outputIdentifiers) {
    if ((Script.outputIdentifiers[type] as () => boolean).bind(this)()) {
      return Script.types[type]
    }
  }
  return Script.types.UNKNOWN
}

Script.inputIdentifiers = {}
Script.inputIdentifiers.PUBKEY_IN = Script.prototype.isPublicKeyIn
Script.inputIdentifiers.PUBKEYHASH_IN = Script.prototype.isPublicKeyHashIn
Script.inputIdentifiers.MULTISIG_IN = Script.prototype.isMultisigIn
Script.inputIdentifiers.SCRIPTHASH_IN = Script.prototype.isScriptHashIn

/**
 * @returns {object} The Script type if it is a known form,
 * or Script.UNKNOWN if it isn't
 */
Script.prototype.classifyInput = function (this: Script) {
  for (const type in Script.inputIdentifiers) {
    if ((Script.inputIdentifiers[type] as () => boolean).bind(this)()) {
      return Script.types[type]
    }
  }
  return Script.types.UNKNOWN
}

/**
 * @returns {boolean} if script is one of the known types
 */
Script.prototype.isStandard = function (this: Script) {
  // TODO: Add BIP62 compliance
  return this.classify() !== Script.types.UNKNOWN
}

// Script construction methods

/**
 * Adds a script element at the start of the script.
 * @param {*} obj a string, number, Opcode, Buffer, or object to add
 * @returns {Script} this script instance
 */
Script.prototype.prepend = function (this: Script, obj: ScriptAddable) {
  this._addByType(obj, true)
  return this
}

/**
 * Compares a script with another script
 */
Script.prototype.equals = function (this: Script, script: Script) {
  $.checkState(script instanceof Script, 'Must provide another script')
  if (this.chunks.length !== script.chunks.length) {
    return false
  }
  let i
  for (i = 0; i < this.chunks.length; i++) {
    if (Buffer.isBuffer((this.chunks[i] as ScriptChunk).buf) && !Buffer.isBuffer((script.chunks[i] as ScriptChunk).buf)) {
      return false
    }
    if (Buffer.isBuffer((this.chunks[i] as ScriptChunk).buf) && !(this.chunks[i] as ScriptChunk).buf!.equals((script.chunks[i] as ScriptChunk).buf as Buffer)) {
      return false
    } else if ((this.chunks[i] as ScriptChunk).opcodenum !== (script.chunks[i] as ScriptChunk).opcodenum) {
      return false
    }
  }
  return true
}

/**
 * Adds a script element to the end of the script.
 *
 * @param {*} obj a string, number, Opcode, Buffer, or object to add
 * @returns {Script} this script instance
 *
 */
Script.prototype.add = function (this: Script, obj: ScriptAddable) {
  this._addByType(obj, false)
  return this
}

Script.prototype._addByType = function (this: Script, obj: ScriptAddable, prepend: boolean) {
  if (typeof obj === 'string') {
    this._addOpcode(obj, prepend)
  } else if (typeof obj === 'number') {
    this._addOpcode(obj, prepend)
  } else if (obj instanceof Opcode) {
    this._addOpcode(obj, prepend)
  } else if (Buffer.isBuffer(obj)) {
    this._addBuffer(obj, prepend)
  } else if (obj instanceof Script) {
    this.chunks = this.chunks.concat(obj.chunks)
  } else if (typeof obj === 'object') {
    this._insertAtPosition(obj, prepend)
  } else {
    throw new Error('Invalid script chunk')
  }
}

Script.prototype._insertAtPosition = function (this: Script, op: ScriptChunk, prepend: boolean) {
  if (prepend) {
    this.chunks.unshift(op)
  } else {
    this.chunks.push(op)
  }
}

Script.prototype._addOpcode = function (this: Script, opcode: number | string | Opcode, prepend: boolean) {
  let op
  if (typeof opcode === 'number') {
    op = opcode
  } else if (opcode instanceof Opcode) {
    op = opcode.toNumber()
  } else {
    op = Opcode(opcode).toNumber()
  }
  this._insertAtPosition({
    opcodenum: op
  }, prepend)
  return this
}

Script.prototype._addBuffer = function (this: Script, buf: Buffer, prepend: boolean) {
  let opcodenum
  const len = buf.length
  if (len >= 0 && len < Opcode.OP_PUSHDATA1) {
    opcodenum = len
  } else if (len < Math.pow(2, 8)) {
    opcodenum = Opcode.OP_PUSHDATA1
  } else if (len < Math.pow(2, 16)) {
    opcodenum = Opcode.OP_PUSHDATA2
  } else if (len < Math.pow(2, 32)) {
    opcodenum = Opcode.OP_PUSHDATA4
  } else {
    throw new Error('You can\'t push that much data')
  }
  this._insertAtPosition({
    buf,
    len,
    opcodenum
  }, prepend)
  return this
}

Script.prototype.removeCodeseparators = function (this: Script) {
  const chunks = []
  for (let i = 0; i < this.chunks.length; i++) {
    if ((this.chunks[i] as ScriptChunk).opcodenum !== Opcode.OP_CODESEPARATOR) {
      chunks.push(this.chunks[i])
    }
  }
  this.chunks = chunks as ScriptChunk[]
  return this
}

// high level script builder methods

/**
 * @returns {Script} a new Multisig output script for given public keys,
 * requiring m of those public keys to spend
 * @param {PublicKey[]} publicKeys - list of all public keys controlling the output
 * @param {number} threshold - amount of required signatures to spend the output
 * @param {Object=} opts - Several options:
 *        - noSorting: defaults to false, if true, don't sort the given
 *                      public keys before creating the script
 */
Script.buildMultisigOut = function (publicKeys: PublicKeyLike[], threshold: number, opts?: MultisigOpts) {
  $.checkArgument(threshold <= publicKeys.length,
    'Number of required signatures must be less than or equal to the number of public keys')
  opts = opts || {}
  const script = new Script()
  script.add(Opcode.smallInt(threshold))
  // Normalized to PublicKey once, under its own name, so the type follows the
  // value instead of the parameter's looser input shape.
  const keys: PublicKey[] = _.map(publicKeys, (k: PublicKeyLike) => new (publicKeyClass())(k))
  let sorted = keys
  if (!opts.noSorting) {
    // NOT cosmetic: the sort decides the script, and therefore the address.
    sorted = keys.map((k) => k.toString()).sort().map((k) => new (publicKeyClass())(k))
  }
  for (let i = 0; i < sorted.length; i++) {
    script.add(sorted[i]!.toBuffer())
  }
  script.add(Opcode.smallInt(keys.length))
  script.add(Opcode.OP_CHECKMULTISIG)
  return script
}

/**
 * A new Multisig input script for the given public keys, requiring m of those public keys to spend
 *
 * @param {PublicKey[]} pubkeys list of all public keys controlling the output
 * @param {number} threshold amount of required signatures to spend the output
 * @param {Array} signatures and array of signature buffers to append to the script
 * @param {Object=} opts
 * @param {boolean=} opts.noSorting don't sort the given public keys before creating the script (false by default)
 * @param {Script=} opts.cachedMultisig don't recalculate the redeemScript
 *
 * @returns {Script}
 */
Script.buildMultisigIn = function (pubkeys: PublicKeyLike[], threshold: number, signatures: Array<Buffer | Signature>, opts?: MultisigOpts) {
  $.checkArgument(_.isArray(pubkeys))
  $.checkArgument(_.isNumber(threshold))
  $.checkArgument(_.isArray(signatures))
  opts = opts || {}
  const s = new Script()
  s.add(Opcode.OP_0)
  _.each(signatures, function (signature) {
    $.checkArgument(Buffer.isBuffer(signature), 'Signatures must be an array of Buffers')
    // TODO: allow signatures to be an array of Signature objects
    s.add(signature as Buffer)
  })
  return s
}

/**
 * A new P2SH Multisig input script for the given public keys, requiring m of those public keys to spend
 *
 * @param {PublicKey[]} pubkeys list of all public keys controlling the output
 * @param {number} threshold amount of required signatures to spend the output
 * @param {Array} signatures and array of signature buffers to append to the script
 * @param {Object=} opts
 * @param {boolean=} opts.noSorting don't sort the given public keys before creating the script (false by default)
 * @param {Script=} opts.cachedMultisig don't recalculate the redeemScript
 *
 * @returns {Script}
 */
Script.buildP2SHMultisigIn = function (pubkeys: PublicKeyLike[], threshold: number, signatures: Array<Buffer | Signature>, opts?: MultisigOpts) {
  $.checkArgument(_.isArray(pubkeys))
  $.checkArgument(_.isNumber(threshold))
  $.checkArgument(_.isArray(signatures))
  opts = opts || {}
  const s = new Script()
  s.add(Opcode.OP_0)
  _.each(signatures, function (signature) {
    $.checkArgument(Buffer.isBuffer(signature), 'Signatures must be an array of Buffers')
    // TODO: allow signatures to be an array of Signature objects
    s.add(signature as Buffer)
  })
  s.add((opts.cachedMultisig || Script.buildMultisigOut(pubkeys, threshold, opts)).toBuffer())
  return s
}

/**
 * @returns {Script} a new pay to public key hash output for the given
 * address or public key
 * @param {(Address|PublicKey)} to - destination address or public key
 */
Script.buildPublicKeyHashOut = function (to: AddressLike) {
  $.checkArgument(!_.isUndefined(to))
  $.checkArgument(to instanceof (publicKeyClass() as new () => unknown) || to instanceof (addressClass() as new () => unknown) || _.isString(to))
  // Three accepted inputs, one internal form. The Address gets its own binding
  // rather than being written back over the parameter.
  let addr: Address
  if (to instanceof (publicKeyClass() as new () => unknown)) {
    addr = (to as PublicKey).toAddress() as Address
  } else if (_.isString(to)) {
    addr = new (addressClass())(to)
  } else {
    addr = to as Address
  }
  const s = new Script()
  s.add(Opcode.OP_DUP)
    .add(Opcode.OP_HASH160)
    .add(addr.hashBuffer)
    .add(Opcode.OP_EQUALVERIFY)
    .add(Opcode.OP_CHECKSIG)
  s._network = addr.network
  return s
}

/**
 * @returns {Script} a new pay to public key output for the given
 *  public key
 */
Script.buildPublicKeyOut = function (pubkey: PublicKey) {
  $.checkArgument(pubkey instanceof (publicKeyClass() as new () => unknown))
  const s = new Script()
  s.add(pubkey.toBuffer())
    .add(Opcode.OP_CHECKSIG)
  return s
}

/**
 * @returns {Script} a new OP_RETURN script with data
 * @param {(string|Buffer|Array)} data - the data to embed in the output - it is a string, buffer, or array of strings or buffers
 * @param {(string)} encoding - the type of encoding of the string(s)
 */
Script.buildDataOut = function (data?: string | Buffer | Array<string | Buffer | undefined>, encoding?: BufferEncoding) {
  $.checkArgument(_.isUndefined(data) || _.isString(data) || _.isArray(data) || Buffer.isBuffer(data))
  // One value or many; normalize to the array form under its own name.
  const datas: Array<string | Buffer | undefined> = _.isArray(data) ? data : [data]
  const s = new Script()
  s.add(Opcode.OP_RETURN)
  for (let data of datas) {
    $.checkArgument(_.isUndefined(data) || _.isString(data) || Buffer.isBuffer(data))
    if (_.isString(data)) {
      data = Buffer.from(data, encoding)
    }
    if (!_.isUndefined(data)) {
      s.add(data)
    }
  }
  return s
}

/**
 * @returns {Script} a new OP_RETURN script with data
 * @param {(string|Buffer|Array)} data - the data to embed in the output - it is a string, buffer, or array of strings or buffers
 * @param {(string)} encoding - the type of encoding of the string(s)
 */
Script.buildSafeDataOut = function (data?: string | Buffer | Array<string | Buffer | undefined>, encoding?: BufferEncoding) {
  const s2 = Script.buildDataOut(data, encoding)
  const s1 = new Script()
  s1.add(Opcode.OP_FALSE)
  s1.add(s2)
  return s1
}

/**
 * @param {Script|Address} script - the redeemScript for the new p2sh output.
 *    It can also be a p2sh address
 * @returns {Script} new pay to script hash script for given script
 */
Script.buildScriptHashOut = function (script: Script | Address) {
  $.checkArgument(script instanceof Script ||
    (script instanceof (addressClass() as new () => unknown) && (script as { isPayToScriptHash: () => boolean }).isPayToScriptHash()))
  const s = new Script()
  s.add(Opcode.OP_HASH160)
    .add(script instanceof (addressClass() as new () => unknown) ? (script as { hashBuffer: Buffer }).hashBuffer : Hash.sha256ripemd160(script.toBuffer()))
    .add(Opcode.OP_EQUAL)

  s._network = (script as Script)._network ?? (script as Address).network
  return s
}

/**
 * Builds a scriptSig (a script for an input) that signs a public key output script.
 *
 * @param {Signature|Buffer} signature - a Signature object, or the signature in DER canonical encoding
 * @param {number=} sigtype - the type of the signature (defaults to SIGHASH_ALL)
 */
Script.buildPublicKeyIn = function (signature: Buffer | Signature, sigtype?: number) {
  $.checkArgument(signature instanceof Signature || Buffer.isBuffer(signature))
  $.checkArgument(_.isUndefined(sigtype) || _.isNumber(sigtype))
  if (signature instanceof Signature) {
    signature = signature.toBuffer()
  }
  const script = new Script()
  script.add(Buffer.concat([
    signature,
    Buffer.from([(sigtype || Signature.SIGHASH_ALL) & 0xff])
  ]))
  return script
}

/**
 * Builds a scriptSig (a script for an input) that signs a public key hash
 * output script.
 *
 * @param {Buffer|string|PublicKey} publicKey
 * @param {Signature|Buffer} signature - a Signature object, or the signature in DER canonical encoding
 * @param {number=} sigtype - the type of the signature (defaults to SIGHASH_ALL)
 */
Script.buildPublicKeyHashIn = function (publicKey: PublicKeyLike, signature: Buffer | Signature, sigtype?: number) {
  $.checkArgument(signature instanceof Signature || Buffer.isBuffer(signature))
  $.checkArgument(_.isUndefined(sigtype) || _.isNumber(sigtype))
  if (signature instanceof Signature) {
    signature = signature.toBuffer()
  }
  const script = new Script()
    .add(Buffer.concat([
      signature,
      Buffer.from([(sigtype || Signature.SIGHASH_ALL) & 0xff])
    ]))
    .add(new (publicKeyClass())(publicKey).toBuffer())
  return script
}

/**
 * @returns {Script} an empty script
 */
Script.empty = function () {
  return new Script()
}

/**
 * @returns {Script} a new pay to script hash script that pays to this script
 */
Script.prototype.toScriptHashOut = function (this: Script) {
  return Script.buildScriptHashOut(this)
}

/**
 * @return {Script} an output script built from the address
 */
Script.fromAddress = function (address: AddressLike) {
  const addr: Address = addressClass()(address)
  if (addr.isPayToScriptHash()) {
    return Script.buildScriptHashOut(addr)
  } else if (addr.isPayToPublicKeyHash()) {
    return Script.buildPublicKeyHashOut(addr)
  }
  throw new (scriptErr('UnrecognizedAddress'))(addr)
}

/**
 * Will return the associated address information object
 * @return {Address|boolean}
 */
Script.prototype.getAddressInfo = function (this: Script, opts?: { network?: NetworkLike }) {
  if (this._isInput) {
    return this._getInputAddressInfo()
  } else if (this._isOutput) {
    return this._getOutputAddressInfo()
  } else {
    const info = this._getOutputAddressInfo()
    if (!info) {
      return this._getInputAddressInfo()
    }
    return info as ScriptAddressInfo
  }
}

/**
 * Will return the associated output scriptPubKey address information object
 * @return {Address|boolean}
 * @private
 */
Script.prototype._getOutputAddressInfo = function (this: Script) {
  const info: Partial<ScriptAddressInfo> = {}
  if (this.isScriptHashOut()) {
    info.hashBuffer = this.getData()
    info.type = addressClass().PayToScriptHash
  } else if (this.isPublicKeyHashOut()) {
    info.hashBuffer = this.getData()
    info.type = addressClass().PayToPublicKeyHash
  } else {
    return false
  }
  return info as ScriptAddressInfo
}

/**
 * Will return the associated input scriptSig address information object
 * @return {Address|boolean}
 * @private
 */
Script.prototype._getInputAddressInfo = function (this: Script) {
  const info: Partial<ScriptAddressInfo> = {}
  if (this.isPublicKeyHashIn()) {
    // hash the publickey found in the scriptSig
    info.hashBuffer = Hash.sha256ripemd160((this.chunks[1] as ScriptChunk).buf as Buffer)
    info.type = addressClass().PayToPublicKeyHash
  } else if (this.isScriptHashIn()) {
    // hash the redeemscript found at the end of the scriptSig
    info.hashBuffer = Hash.sha256ripemd160((this.chunks[this.chunks.length - 1] as ScriptChunk).buf as Buffer)
    info.type = addressClass().PayToScriptHash
  } else {
    return false
  }
  return info as ScriptAddressInfo
}

/**
 * @param {Network=} network
 * @return {Address|boolean} the associated address for this script if possible, or false
 */
Script.prototype.toAddress = function (this: Script, network?: NetworkLike) {
  const info = this.getAddressInfo()
  if (!info) {
    return false
  }
  info.network = Networks.get(network) || this._network || Networks.defaultNetwork
  return new (addressClass())(info)
}

/**
 * Analogous to bitcoind's FindAndDelete. Find and delete equivalent chunks,
 * typically used with push data chunks.  Note that this will find and delete
 * not just the same data, but the same data with the same push data op as
 * produced by default. i.e., if a pushdata in a tx does not use the minimal
 * pushdata op, then when you try to remove the data it is pushing, it will not
 * be removed, because they do not use the same pushdata op.
 */
Script.prototype.findAndDelete = function (this: Script, script: Script) {
  const buf = script.toBuffer()
  const hex = buf.toString('hex')
  for (let i = 0; i < this.chunks.length; i++) {
    const script2 = Script({
      chunks: [this.chunks[i]]
    })
    const buf2 = script2.toBuffer()
    const hex2 = buf2.toString('hex')
    if (hex === hex2) {
      this.chunks.splice(i, 1)
    }
  }
  return this
}

/**
 * Comes from bitcoind's script interpreter CheckMinimalPush function
 * @returns {boolean} if the chunk {i} is the smallest way to push that particular data.
 */
Script.prototype.checkMinimalPush = function (this: Script, i: number) {
  const chunk = this.chunks[i] as ScriptChunk
  const buf = chunk.buf
  const opcodenum = chunk.opcodenum
  if (!buf) {
    return true
  }
  if (buf.length === 0) {
    // Could have used OP_0.
    return opcodenum === Opcode.OP_0
  } else if (buf.length === 1 && (buf[0] as number) >= 1 && (buf[0] as number) <= 16) {
    // Could have used OP_1 .. OP_16.
    return opcodenum === Opcode.OP_1 + ((buf[0] as number) - 1)
  } else if (buf.length === 1 && buf[0] === 0x81) {
    // Could have used OP_1NEGATE
    return opcodenum === Opcode.OP_1NEGATE
  } else if (buf.length <= 75) {
    // Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
    return opcodenum === buf.length
  } else if (buf.length <= 255) {
    // Could have used OP_PUSHDATA.
    return opcodenum === Opcode.OP_PUSHDATA1
  } else if (buf.length <= 65535) {
    // Could have used OP_PUSHDATA2.
    return opcodenum === Opcode.OP_PUSHDATA2
  }
  return true
}

/**
 * Comes from bitcoind's script DecodeOP_N function
 * @param {number} opcode
 * @returns {number} numeric value in range of 0 to 16
 */
Script.prototype._decodeOP_N = function (this: Script, opcode: number) {
  if (opcode === Opcode.OP_0) {
    return 0
  } else if (opcode >= Opcode.OP_1 && opcode <= Opcode.OP_16) {
    return opcode - (Opcode.OP_1 - 1)
  } else {
    throw new Error('Invalid opcode: ' + JSON.stringify(opcode))
  }
}

/**
 * Comes from bitcoind's script GetSigOpCount(boolean) function
 * @param {boolean} use current (true) or pre-version-0.6 (false) logic
 * @returns {number} number of signature operations required by this script
 */
Script.prototype.getSignatureOperationsCount = function (this: Script, accurate?: boolean) {
  accurate = (_.isUndefined(accurate) ? true : accurate)
  const self = this
  let n = 0
  let lastOpcode = Opcode.OP_INVALIDOPCODE
  _.each(self.chunks, function getChunk (chunk) {
    const opcode = chunk.opcodenum
    if (opcode === Opcode.OP_CHECKSIG || opcode === Opcode.OP_CHECKSIGVERIFY) {
      n++
    } else if (opcode === Opcode.OP_CHECKMULTISIG || opcode === Opcode.OP_CHECKMULTISIGVERIFY) {
      if (accurate && lastOpcode >= Opcode.OP_1 && lastOpcode <= Opcode.OP_16) {
        n += self._decodeOP_N(lastOpcode)
      } else {
        n += 20
      }
    }
    lastOpcode = opcode
  })
  return n
}

export = Script
