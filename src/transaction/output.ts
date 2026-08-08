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
      this.setScript(script)
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
      this._satoshisBN = num
      this._satoshis = num.toNumber()
    } else if (_.isString(num)) {
      this._satoshis = parseInt(num)
      this._satoshisBN = BN.fromNumber(this._satoshis)
    } else {
      $.checkArgument(
        JSUtil.isNaturalNumber(num),
        'Output satoshis is not a natural number'
      )
      this._satoshisBN = BN.fromNumber(num as number)
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
  if (sats !== (this._satoshisBN as BN).toNumber()) {
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
    return this._satoshisBN
  },
  set: function (this: Output, num: BN) {
    this._satoshisBN = num
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
  this._scriptBuffer = buffer
  try {
    this._script = scriptCtor().fromBuffer(this._scriptBuffer)
    ;(this._script as import('../script/script.types').Script)._isOutput = true
  } catch (e) {
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

Output.fromBufferReader = function (br: any): Output {
  // Field order is the consensus serialization order; each read advances br.
  const satoshis = br.readUInt64LEBN()
  const size = br.readVarintNum()
  const script = size !== 0 ? br.read(size) : Buffer.from([])
  return new (Output as OutputConstructor)({ satoshis, script })
}

Output.prototype.toBufferWriter = function (this: Output, writer?: any): any {
  if (writer == null) {
    writer = new BufferWriter()
  }
  writer.writeUInt64LEBN(this._satoshisBN)
  const script = this._scriptBuffer as Buffer
  writer.writeVarintNum(script.length)
  writer.write(script)
  return writer
}

// 8    value
// ???  script size (VARINT)
// ???  script
Output.prototype.getSize = function (this: Output): number {
  const scriptSize = this.script.toBuffer().length
  const varintSize = Varint(scriptSize).toBuffer().length
  return 8 + varintSize + scriptSize
}

export = Output
