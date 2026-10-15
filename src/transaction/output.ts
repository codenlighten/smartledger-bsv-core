'use strict'

import _ = require('../util/_')
import BN = require('../crypto/bn')
import JSUtil = require('../util/js')
import BufferWriter = require('../encoding/bufferwriter')
import Varint = require('../encoding/varint')
import $ = require('../util/preconditions')
import errors = require('../errors')
import type { Output, OutputConstructor } from './types'
import type { ScriptConstructor } from '../script/script.types'
import type { BufferReader } from '../encoding/types'

// Runtime edge into the script <-> transaction cycle: resolved at call time.
const scriptCtor = (): ScriptConstructor => require('../script')

const MAX_SAFE_INTEGER = 0x1fffffffffffff

const Output = function Output (this: Output, args: { satoshis?: unknown, script?: unknown }) {
  if (!(this instanceof Output)) {
    return new (Output as OutputConstructor)(args)
  }
  if (_.isObject(args)) {
    this.satoshis = args.satoshis as number
    if (Buffer.isBuffer(args.script)) {
      this._scriptBuffer = args.script
    } else {
      let script: unknown
      if (_.isString(args.script) && JSUtil.isHexa(args.script)) {
        script = Buffer.from(args.script, 'hex')
      } else {
        script = args.script
      }
      this.setScript(script as Buffer | string)
    }
  } else {
    throw new TypeError('Unrecognized argument for Output')
  }
} as unknown as OutputConstructor

Object.defineProperty(Output.prototype, 'script', {
  configurable: false,
  enumerable: true,
  get: function (this: Output) {
    if (this._script != null) {
      return this._script
    } else {
      this.setScriptFromBuffer(this._scriptBuffer as Buffer)
      return this._script
    }
  }
})

Object.defineProperty(Output.prototype, 'satoshis', {
  configurable: false,
  enumerable: true,
  get: function (this: Output) {
    return this._satoshis
  },
  set: function (this: Output, num: unknown) {
    if (num instanceof BN) {
      this._satoshisBN! = num
      this._satoshis = num.toNumber()
    } else if (_.isString(num)) {
      this._satoshis = parseInt(num)
      this._satoshisBN! = BN.fromNumber(this._satoshis)
    } else {
      $.checkArgument(
        JSUtil.isNaturalNumber(num),
        'Output satoshis is not a natural number'
      )
      this._satoshisBN! = BN.fromNumber(num as number)
      this._satoshis = num as number
    }
    $.checkState(
      JSUtil.isNaturalNumber(this._satoshis),
      'Output satoshis is not a natural number'
    )
  }
})

Output.prototype.invalidSatoshis = function (this: Output): string | false {
  // _satoshis is always set by the constructor via the satoshis setter.
  const sats = this._satoshis as number
  if (sats > MAX_SAFE_INTEGER) {
    return 'transaction txout satoshis greater than max safe integer'
  }
  if (sats !== (this._satoshisBN! as BN).toNumber()) {
    return 'transaction txout satoshis has corrupted value'
  }
  if (sats < 0) {
    return 'transaction txout negative'
  }
  return false
}

Object.defineProperty(Output.prototype, 'satoshisBN', {
  configurable: false,
  enumerable: true,
  get: function (this: Output) {
    return this._satoshisBN!
  },
  set: function (this: Output, num: BN) {
    this._satoshisBN! = num
    this._satoshis = num.toNumber()
    $.checkState(
      JSUtil.isNaturalNumber(this._satoshis),
      'Output satoshis is not a natural number'
    )
  }
})

Output.prototype.toObject = Output.prototype.toJSON = function toObject (this: Output): Record<string, unknown> {
  return {
    satoshis: this.satoshis,
    script: (this._scriptBuffer as Buffer).toString('hex')
  }
}

Output.fromObject = function (data: Record<string, unknown>): Output {
  return new (Output as OutputConstructor)(data)
}

Output.prototype.setScriptFromBuffer = function (this: Output, buffer: Buffer): void {
  // Checked BEFORE the assignment, and that order is the point. This used to assign first, so a
  // caller reaching this from JavaScript, or through an `as any`, with a string or `undefined`
  // left the output holding a non-Buffer `_scriptBuffer`: the throw came from inside the parser,
  // and every LATER read of `.script` threw too, naming neither this method nor the argument.
  // The null-script guards elsewhere read `_scriptBuffer.length` and
  // `_scriptBuffer.toString('hex')`, so they assume what this now enforces: every
  // `_scriptBuffer` in a live object is a Buffer. The declared parameter type does not reach a
  // JavaScript caller.
  $.checkArgument(Buffer.isBuffer(buffer), 'Output script buffer must be a Buffer')
  this._scriptBuffer = buffer
  try {
    this._script = scriptCtor().fromBuffer(this._scriptBuffer)
    ;(this._script as import('../script/script.types').Script)._isOutput = true
  } catch (e) {
    // `Script.fromBuffer` is now total: every byte string parses, because the parser keeps a
    // cut-off length prefix instead of throwing and a decode failure surfaces at USE, as it
    // does in the node. So this branch is unreachable from real bytes today.
    //
    // It stays. A guard deleted because nothing currently reaches it is how the next parse
    // failure becomes an uncaught throw at transaction construction, and the whole point of
    // this one is that a transaction carrying an output we cannot read must still be
    // constructible, stored and relayed.
    if (e instanceof ((errors.Script as Record<string, unknown>).InvalidBuffer as new () => Error)) {
      this._script = null
    } else {
      throw e
    }
  }
}

Output.prototype.setScript = function (this: Output, script: unknown): Output {
  const Script = scriptCtor()
  if (script instanceof (Script as unknown as new () => unknown)) {
    const s = script as import('../script/script.types').Script
    this._scriptBuffer = s.toBuffer()
    this._script = s
    s._isOutput = true
  } else if (_.isString(script)) {
    const s = Script.fromString(script)
    this._script = s
    this._scriptBuffer = s.toBuffer()
    s._isOutput = true
  } else if (Buffer.isBuffer(script)) {
    this.setScriptFromBuffer(script)
  } else {
    throw new TypeError('Invalid argument type: script')
  }
  return this
}

Output.prototype.inspect = function (this: Output): string {
  let scriptStr: string
  if (this.script != null) {
    scriptStr = this.script.inspect()
  } else {
    scriptStr = (this._scriptBuffer as Buffer).toString('hex')
  }
  return '<Output (' + this.satoshis + ' sats) ' + scriptStr + '>'
}

Output.fromBufferReader = function (br: BufferReader): Output {
  // Field order is the consensus serialization order; each read advances br.
  const satoshis = br.readUInt64LEBN()
  const size = br.readVarintNum()
  const script = size !== 0 ? br.read(size) : Buffer.from([])
  return new (Output as OutputConstructor)({ satoshis, script })
}

Output.prototype.toBufferWriter = function (this: Output, writer?: BufferWriter): BufferWriter {
  if (writer == null) {
    writer = new BufferWriter()
  }
  writer.writeUInt64LEBN(this._satoshisBN!)
  const script = this._scriptBuffer as Buffer
  writer.writeVarintNum(script.length)
  writer.write(script)
  return writer
}

// 8    value
// ???  script size (VARINT)
// ???  script
Output.prototype.getSize = function (this: Output): number {
  // `this.script` is null when the raw bytes could not be decoded (see setScriptFromBuffer),
  // which happens for outputs the node accepts and mines, so the size must still be
  // answerable. ONLY that case falls back to the raw buffer. A parsed script keeps the
  // existing calculation, because a caller may have mutated the Script object in place and
  // getSize() has always measured the object — `_scriptBuffer` is what actually serializes,
  // and the two disagree after such a mutation. Making them agree is a separate change with
  // its own behaviour consequences; both sides are pinned in
  // test/transaction/output_unparseable_script.js.
  const scriptSize = this.script === null
    ? (this._scriptBuffer as Buffer).length
    : this.script.toBuffer().length
  const varintSize = Varint(scriptSize).toBuffer().length
  return 8 + varintSize + scriptSize
}

export = Output
