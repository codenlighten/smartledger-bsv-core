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
