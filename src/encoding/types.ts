/**
 * Shared shapes for the encoding modules.
 *
 * These live apart from their implementations because those modules use
 * `export =` to preserve their CommonJS `require()` shape (a bare
 * constructor), and TypeScript forbids an export assignment alongside other
 * exported members.
 */

/**
 * Structural type for the big-number values the encoders accept.
 *
 * Declared structurally rather than importing crypto/bn, which is still
 * JavaScript; importing it would pull an untyped dependency into the generated
 * declarations. Replace with the real BN type once crypto/bn is converted.
 */
export interface BNLike {
  toBuffer: (opts: { size: number }) => Buffer
  toNumber: () => number
}

export interface BufferWriter {
  bufs: Buffer[]
  bufLen: number

  set: (obj: { bufs?: Buffer[] }) => BufferWriter
  toBuffer: () => Buffer
  concat: () => Buffer
  write: (buf: Buffer) => BufferWriter
  writeReverse: (buf: Buffer) => BufferWriter
  writeUInt8: (n: number) => BufferWriter
  writeUInt16BE: (n: number) => BufferWriter
  writeUInt16LE: (n: number) => BufferWriter
  writeUInt32BE: (n: number) => BufferWriter
  writeInt32LE: (n: number) => BufferWriter
  writeUInt32LE: (n: number) => BufferWriter
  writeUInt64BEBN: (bn: BNLike) => BufferWriter
  writeUInt64LEBN: (bn: BNLike) => BufferWriter
  writeVarintNum: (n: number) => BufferWriter
  writeVarintBN: (bn: BNLike) => BufferWriter
}

export interface BufferWriterConstructor {
  new (obj?: { bufs?: Buffer[] }): BufferWriter
  (obj?: { bufs?: Buffer[] }): BufferWriter
  varintBufNum: (n: number) => Buffer
  varintBufBN: (bn: BNLike) => Buffer
}

export interface Base58 {
  buf: Buffer | undefined
  set: (obj: { buf?: Buffer }) => Base58
  fromBuffer: (buf: Buffer) => Base58
  fromString: (str: string) => Base58
  toBuffer: () => Buffer
  toHex: () => string
  toString: () => string
}

export interface Base58Constructor {
  new (obj?: Buffer | string): Base58
  (obj?: Buffer | string): Base58
  validCharacters: (chars: string | Buffer) => boolean
  encode: (buf: Buffer) => string
  decode: (str: string) => Buffer
  fromBuffer: (buf: Buffer) => Base58
  fromHex: (hex: string) => Base58
  fromString: (str: string) => Base58
}

export interface BufferReader {
  buf: Buffer
  pos: number

  set: (obj: { buf?: Buffer, pos?: number }) => BufferReader
  eof: () => boolean
  finished: () => boolean
  read: (len: number) => Buffer
  readAll: () => Buffer
  readUInt8: () => number
  readUInt16BE: () => number
  readUInt16LE: () => number
  readUInt32BE: () => number
  readUInt32LE: () => number
  readInt32LE: () => number
  readUInt64BEBN: () => import('bn.js')
  readUInt64LEBN: () => import('bn.js')
  readVarintNum: () => number
  readVarLengthBuffer: () => Buffer
  readVarintBuf: () => Buffer
  readVarintBN: () => import('bn.js')
  reverse: () => BufferReader
  readReverse: (len?: number) => Buffer
}

export interface BufferReaderConstructor {
  new (buf?: Buffer | string | { buf?: Buffer, pos?: number }): BufferReader
  (buf?: Buffer | string | { buf?: Buffer, pos?: number }): BufferReader
}

export interface Varint {
  buf: Buffer
  set: (obj: { buf?: Buffer }) => Varint
  fromString: (str: string) => Varint
  toString: () => string
  fromBuffer: (buf: Buffer) => Varint
  fromBufferReader: (br: BufferReader) => Varint
  fromBN: (bn: import('bn.js')) => Varint
  fromNumber: (num: number) => Varint
  toBuffer: () => Buffer
  toBN: () => import('bn.js')
  toNumber: () => number
}

export interface VarintConstructor {
  new (buf?: Buffer | number | import('bn.js') | { buf?: Buffer }): Varint
  (buf?: Buffer | number | import('bn.js') | { buf?: Buffer }): Varint
}

export interface Base58Check {
  buf: Buffer | undefined
  set: (obj: { buf?: Buffer }) => Base58Check
  fromBuffer: (buf: Buffer) => Base58Check
  fromString: (str: string) => Base58Check
  toBuffer: () => Buffer
  toHex: () => string
  toString: () => string
}

export interface Base58CheckConstructor {
  new (obj?: Buffer | string): Base58Check
  (obj?: Buffer | string): Base58Check
  validChecksum: (data: Buffer | string, checksum?: Buffer | string) => boolean
  decode: (s: string) => Buffer
  checksum: (buffer: Buffer) => Buffer
  encode: (buf: Buffer) => string
  fromBuffer: (buf: Buffer) => Base58Check
  fromHex: (hex: string) => Base58Check
  fromString: (str: string) => Base58Check
}
