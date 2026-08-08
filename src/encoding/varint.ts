'use strict'

import BufferWriter = require('./bufferwriter')
import BufferReader = require('./bufferreader')
import BN = require('bn.js')
import type { Varint, VarintConstructor, BufferReader as BufferReaderType } from './types'

const Varint = function Varint (this: Varint, buf?: Buffer | number | BN | { buf?: Buffer }) {
  if (!(this instanceof Varint)) { return new (Varint as VarintConstructor)(buf) }
  if (Buffer.isBuffer(buf)) {
    this.buf = buf
  } else if (typeof buf === 'number') {
    const num = buf
    this.fromNumber(num)
  } else if (buf instanceof BN) {
    const bn = buf
    this.fromBN(bn)
  } else if (buf != null) {
    const obj = buf as { buf?: Buffer }
    this.set(obj)
  }
} as unknown as VarintConstructor

Varint.prototype.set = function (this: Varint, obj: { buf?: Buffer }): Varint {
  this.buf = obj.buf ?? this.buf
  return this
}

Varint.prototype.fromString = function (this: Varint, str: string): Varint {
  this.set({
    buf: Buffer.from(str, 'hex')
  })
  return this
}

Varint.prototype.toString = function (this: Varint): string {
  return this.buf.toString('hex')
}

Varint.prototype.fromBuffer = function (this: Varint, buf: Buffer): Varint {
  this.buf = buf
  return this
}

Varint.prototype.fromBufferReader = function (this: Varint, br: BufferReaderType): Varint {
  this.buf = br.readVarintBuf()
  return this
}

Varint.prototype.fromBN = function (this: Varint, bn: BN): Varint {
  this.buf = BufferWriter().writeVarintBN(bn).concat()
  return this
}

Varint.prototype.fromNumber = function (this: Varint, num: number): Varint {
  this.buf = BufferWriter().writeVarintNum(num).concat()
  return this
}

Varint.prototype.toBuffer = function (this: Varint): Buffer {
  return this.buf
}

Varint.prototype.toBN = function (this: Varint): BN {
  return BufferReader(this.buf).readVarintBN()
}

Varint.prototype.toNumber = function (this: Varint): number {
  return BufferReader(this.buf).readVarintNum()
}

export = Varint
