'use strict'

import _ = require('../util/_')
import BN = require('../crypto/bn')
import BufferReader = require('../encoding/bufferreader')
import BufferWriter = require('../encoding/bufferwriter')
import Hash = require('../crypto/hash')
import $ = require('../util/preconditions')
import type { BlockHeader, BlockHeaderConstructor, BlockHeaderObj, BlockHeaderInfo } from './types'
import type { BufferReader as BufferReaderType, BufferWriter as BufferWriterType } from '../encoding/types'

const GENESIS_BITS = 0x1d00ffff

/**
 * Instantiate a BlockHeader from a Buffer, JSON object, or Object with
 * the properties of the BlockHeader
 *
 * @param {*} - A Buffer, JSON string, or Object
 * @returns {BlockHeader} - An instance of block header
 * @constructor
 */
const BlockHeader = function BlockHeader (this: BlockHeader, arg?: BlockHeaderObj | Buffer | string) {
  if (!(this instanceof BlockHeader)) {
    return new (BlockHeader as BlockHeaderConstructor)(arg)
  }
  if (arg === undefined) { throw new TypeError('Unrecognized argument for BlockHeader') }
  const info = (BlockHeader as BlockHeaderConstructor)._from(arg)
  this.version = info.version
  this.prevHash = info.prevHash
  this.merkleRoot = info.merkleRoot
  this.time = info.time
  this.timestamp = info.time
  this.bits = info.bits
  this.nonce = info.nonce

  if (info.hash) {
    $.checkState(
      this.hash === info.hash,
      'Argument object hash property does not match block hash.'
    )
  }

  return this
} as unknown as BlockHeaderConstructor

/**
 * @param {*} - A Buffer, JSON string or Object
 * @returns {Object} - An object representing block header data
 * @throws {TypeError} - If the argument was not recognized
 * @private
 */
BlockHeader._from = function _from (arg: BlockHeaderObj | Buffer | string): BlockHeaderInfo {
  let info: BlockHeaderInfo
  if (Buffer.isBuffer(arg)) {
    info = BlockHeader._fromBufferReader(BufferReader(arg))
  } else if (_.isObject(arg)) {
    info = BlockHeader._fromObject(arg as BlockHeaderObj)
  } else {
    throw new TypeError('Unrecognized argument for BlockHeader')
  }
  return info
}

/**
 * @param {Object} - A JSON string
 * @returns {Object} - An object representing block header data
 * @private
 */
BlockHeader._fromObject = function _fromObject (data: BlockHeaderObj): BlockHeaderInfo {
  $.checkArgument(data, 'data is required')
  // Hex in means DISPLAY order, so it is reversed into the internal
  // little-endian order the serializer expects. Buffers are taken as already
  // internal-order.
  const prevHash: Buffer = _.isString(data.prevHash)
    ? Buffer.from(data.prevHash, 'hex').reverse()
    : data.prevHash
  const merkleRoot: Buffer = _.isString(data.merkleRoot)
    ? Buffer.from(data.merkleRoot, 'hex').reverse()
    : data.merkleRoot
  const info = {
    hash: data.hash,
    version: data.version,
    prevHash,
    merkleRoot,
    time: data.time,
    timestamp: data.time,
    bits: data.bits,
    nonce: data.nonce
  }
  return info
}

/**
 * @param {Object} - A plain JavaScript object
 * @returns {BlockHeader} - An instance of block header
 */
BlockHeader.fromObject = function fromObject (obj: BlockHeaderObj): BlockHeader {
  const info = BlockHeader._fromObject(obj)
  return new BlockHeader(info)
}

/**
 * @param {Binary} - Raw block binary data or buffer
 * @returns {BlockHeader} - An instance of block header
 */
BlockHeader.fromRawBlock = function fromRawBlock (data: Buffer | string): BlockHeader {
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data, 'binary')
  }
  const br = BufferReader(data)
  br.pos = BlockHeader.Constants.START_OF_HEADER
  const info = BlockHeader._fromBufferReader(br)
  return new BlockHeader(info)
}

/**
 * @param {Buffer} - A buffer of the block header
 * @returns {BlockHeader} - An instance of block header
 */
BlockHeader.fromBuffer = function fromBuffer (buf: Buffer): BlockHeader {
  const info = BlockHeader._fromBufferReader(BufferReader(buf))
  return new BlockHeader(info)
}

/**
 * @param {string} - A hex encoded buffer of the block header
 * @returns {BlockHeader} - An instance of block header
 */
BlockHeader.fromString = function fromString (str: string): BlockHeader {
  const buf = Buffer.from(str, 'hex')
  return BlockHeader.fromBuffer(buf)
}

/**
 * @param {BufferReader} - A BufferReader of the block header
 * @returns {Object} - An object representing block header data
 * @private
 */
BlockHeader._fromBufferReader = function _fromBufferReader (br: BufferReaderType): BlockHeaderInfo {
  // Field order is the consensus serialization order and must not be
  // rearranged: each read advances the reader.
  const version = br.readInt32LE()
  const prevHash = br.read(32)
  const merkleRoot = br.read(32)
  const time = br.readUInt32LE()
  const bits = br.readUInt32LE()
  const nonce = br.readUInt32LE()
  return { version, prevHash, merkleRoot, time, bits, nonce }
}

/**
 * @param {BufferReader} - A BufferReader of the block header
 * @returns {BlockHeader} - An instance of block header
 */
BlockHeader.fromBufferReader = function fromBufferReader (br: BufferReaderType): BlockHeader {
  const info = BlockHeader._fromBufferReader(br)
  return new BlockHeader(info)
}

/**
 * @returns {Object} - A plain object of the BlockHeader
 */
BlockHeader.prototype.toObject = BlockHeader.prototype.toJSON = function toObject (this: BlockHeader): BlockHeaderObj {
  return {
    hash: this.hash,
    version: this.version,
    prevHash: Buffer.from(this.prevHash).reverse().toString('hex'),
    merkleRoot: Buffer.from(this.merkleRoot).reverse().toString('hex'),
    time: this.time,
    bits: this.bits,
    nonce: this.nonce
  }
}

/**
 * @returns {Buffer} - A Buffer of the BlockHeader
 */
BlockHeader.prototype.toBuffer = function toBuffer (this: BlockHeader): Buffer {
  return this.toBufferWriter().concat()
}

/**
 * @returns {string} - A hex encoded string of the BlockHeader
 */
BlockHeader.prototype.toString = function toString (this: BlockHeader): string {
  return this.toBuffer().toString('hex')
}

/**
 * @param {BufferWriter} - An existing instance BufferWriter
 * @returns {BufferWriter} - An instance of BufferWriter representation of the BlockHeader
 */
BlockHeader.prototype.toBufferWriter = function toBufferWriter (this: BlockHeader, bw?: BufferWriterType): BufferWriterType {
  if (!bw) {
    bw = new BufferWriter()
  }
  bw.writeInt32LE(this.version)
  bw.write(this.prevHash)
  bw.write(this.merkleRoot)
  bw.writeUInt32LE(this.time)
  bw.writeUInt32LE(this.bits)
  bw.writeUInt32LE(this.nonce)
  return bw
}

/**
 * Returns the target difficulty for this block
 * @param {Number} bits
 * @returns {BN} An instance of BN with the decoded difficulty bits
 */
BlockHeader.prototype.getTargetDifficulty = function getTargetDifficulty (this: BlockHeader, bits?: number): BN {
  bits = bits || this.bits

  let target = new BN(bits & 0xffffff)
  let mov = 8 * ((bits >>> 24) - 3)
  while (mov-- > 0) {
    target = target.mul(new BN(2))
  }
  return target
}

/**
 * @link https://en.bitcoin.it/wiki/Difficulty
 * @return {Number}
 */
BlockHeader.prototype.getDifficulty = function getDifficulty (this: BlockHeader): number {
  const difficulty1TargetBN = this.getTargetDifficulty(GENESIS_BITS).mul(new BN(Math.pow(10, 8)))
  const currentTargetBN = this.getTargetDifficulty()

  let difficultyString = difficulty1TargetBN.div(currentTargetBN).toString(10)
  const decimalPos = difficultyString.length - 8
  difficultyString = difficultyString.slice(0, decimalPos) + '.' + difficultyString.slice(decimalPos)

  return parseFloat(difficultyString)
}

/**
 * @returns {Buffer} - The little endian hash buffer of the header
 */
BlockHeader.prototype._getHash = function hash (this: BlockHeader): Buffer {
  const buf = this.toBuffer()
  return Hash.sha256sha256(buf)
}

const idProperty = {
  configurable: false,
  enumerable: true,
  /**
   * @returns {string} - The big endian hash buffer of the header
   */
  get: function (this: BlockHeader): string {
    if (this._id == null) {
      this._id = BufferReader(this._getHash()).readReverse().toString('hex')
    }
    return this._id
  },
  set: _.noop
}
Object.defineProperty(BlockHeader.prototype, 'id', idProperty)
Object.defineProperty(BlockHeader.prototype, 'hash', idProperty)

/**
 * @returns {Boolean} - If timestamp is not too far in the future
 */
BlockHeader.prototype.validTimestamp = function validTimestamp (this: BlockHeader): boolean {
  const currentTime = Math.round(new Date().getTime() / 1000)
  if (this.time > currentTime + BlockHeader.Constants.MAX_TIME_OFFSET) {
    return false
  }
  return true
}

/**
 * @returns {Boolean} - If the proof-of-work hash satisfies the target difficulty
 */
BlockHeader.prototype.validProofOfWork = function validProofOfWork (this: BlockHeader): boolean {
  const pow = new BN(this.id, 'hex')
  const target = this.getTargetDifficulty()

  if (pow.cmp(target) > 0) {
    return false
  }
  return true
}

/**
 * @returns {string} - A string formatted for the console
 */
BlockHeader.prototype.inspect = function inspect (this: BlockHeader): string {
  return '<BlockHeader ' + this.id + '>'
}

BlockHeader.Constants = {
  START_OF_HEADER: 8, // Start buffer position in raw block data
  MAX_TIME_OFFSET: 2 * 60 * 60, // The max a timestamp can be in the future
  LARGEST_HASH: new BN('10000000000000000000000000000000000000000000000000000000000000000', 'hex')
}

export = BlockHeader
