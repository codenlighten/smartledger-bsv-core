'use strict'

import assert from 'assert'

/**
 * Accumulates buffers and concatenates them once, on demand.
 *
 * NOTE ON SHAPE: this is a constructor *function*, not a `class`, and that is
 * deliberate. Existing code calls it both ways — `new BufferWriter()` and bare
 * `BufferWriter()` (see encoding/varint) — and an ES2020 `class` throws when
 * invoked without `new`. Converting it to a class would be an API break
 * disguised as a refactor. The same pattern applies to the other
 * dual-callable constructors in this library.
 */

import type { BNLike, BufferWriter, BufferWriterConstructor } from './types'

const BufferWriter = function BufferWriter (this: BufferWriter, obj?: { bufs?: Buffer[] }) {
  if (!(this instanceof BufferWriter)) { return new (BufferWriter as BufferWriterConstructor)(obj) }
  this.bufLen = 0
  if (obj != null) { this.set(obj) } else { this.bufs = [] }
} as unknown as BufferWriterConstructor

BufferWriter.prototype.set = function (this: BufferWriter, obj: { bufs?: Buffer[] }): BufferWriter {
  this.bufs = obj.bufs ?? this.bufs ?? []
  this.bufLen = this.bufs.reduce(function (prev, buf) { return prev + buf.length }, 0)
  return this
}

BufferWriter.prototype.toBuffer = function (this: BufferWriter): Buffer {
  return this.concat()
}

BufferWriter.prototype.concat = function (this: BufferWriter): Buffer {
  return Buffer.concat(this.bufs, this.bufLen)
}

BufferWriter.prototype.write = function (this: BufferWriter, buf: Buffer): BufferWriter {
  assert(Buffer.isBuffer(buf))
  this.bufs.push(buf)
  this.bufLen += buf.length
  return this
}

BufferWriter.prototype.writeReverse = function (this: BufferWriter, buf: Buffer): BufferWriter {
  assert(Buffer.isBuffer(buf))
  this.bufs.push(Buffer.from(buf).reverse())
  this.bufLen += buf.length
  return this
}

BufferWriter.prototype.writeUInt8 = function (this: BufferWriter, n: number): BufferWriter {
  const buf = Buffer.alloc(1)
  buf.writeUInt8(n, 0)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeUInt16BE = function (this: BufferWriter, n: number): BufferWriter {
  const buf = Buffer.alloc(2)
  buf.writeUInt16BE(n, 0)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeUInt16LE = function (this: BufferWriter, n: number): BufferWriter {
  const buf = Buffer.alloc(2)
  buf.writeUInt16LE(n, 0)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeUInt32BE = function (this: BufferWriter, n: number): BufferWriter {
  const buf = Buffer.alloc(4)
  buf.writeUInt32BE(n, 0)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeInt32LE = function (this: BufferWriter, n: number): BufferWriter {
  const buf = Buffer.alloc(4)
  buf.writeInt32LE(n, 0)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeUInt32LE = function (this: BufferWriter, n: number): BufferWriter {
  const buf = Buffer.alloc(4)
  buf.writeUInt32LE(n, 0)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeUInt64BEBN = function (this: BufferWriter, bn: BNLike): BufferWriter {
  const buf = bn.toBuffer({ size: 8 })
  this.write(buf)
  return this
}

BufferWriter.prototype.writeUInt64LEBN = function (this: BufferWriter, bn: BNLike): BufferWriter {
  const buf = bn.toBuffer({ size: 8 })
  this.writeReverse(buf)
  return this
}

BufferWriter.prototype.writeVarintNum = function (this: BufferWriter, n: number): BufferWriter {
  const buf = BufferWriter.varintBufNum(n)
  this.write(buf)
  return this
}

BufferWriter.prototype.writeVarintBN = function (this: BufferWriter, bn: BNLike): BufferWriter {
  const buf = BufferWriter.varintBufBN(bn)
  this.write(buf)
  return this
}

BufferWriter.varintBufNum = function (n: number): Buffer {
  let buf: Buffer
  if (n < 253) {
    buf = Buffer.alloc(1)
    buf.writeUInt8(n, 0)
  } else if (n < 0x10000) {
    buf = Buffer.alloc(1 + 2)
    buf.writeUInt8(253, 0)
    buf.writeUInt16LE(n, 1)
  } else if (n < 0x100000000) {
    buf = Buffer.alloc(1 + 4)
    buf.writeUInt8(254, 0)
    buf.writeUInt32LE(n, 1)
  } else {
    buf = Buffer.alloc(1 + 8)
    buf.writeUInt8(255, 0)
    buf.writeInt32LE(n & -1, 1)
    buf.writeUInt32LE(Math.floor(n / 0x100000000), 5)
  }
  return buf
}

BufferWriter.varintBufBN = function (bn: BNLike): Buffer {
  let buf: Buffer
  const n = bn.toNumber()
  if (n < 253) {
    buf = Buffer.alloc(1)
    buf.writeUInt8(n, 0)
  } else if (n < 0x10000) {
    buf = Buffer.alloc(1 + 2)
    buf.writeUInt8(253, 0)
    buf.writeUInt16LE(n, 1)
  } else if (n < 0x100000000) {
    buf = Buffer.alloc(1 + 4)
    buf.writeUInt8(254, 0)
    buf.writeUInt32LE(n, 1)
  } else {
    const bw = new BufferWriter()
    bw.writeUInt8(255)
    bw.writeUInt64LEBN(bn)
    buf = bw.concat()
  }
  return buf
}

export = BufferWriter
