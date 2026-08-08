'use strict'

const { BUFFERS, ADDRESSES, SCRIPTS } = require('../vectors')

const hex = (s) => Buffer.from(s, 'hex')

module.exports = {
  name: 'encoding',
  cases: {
    // --- Base58 --------------------------------------------------------------
    'base58 encode empty': (bsv) => bsv.encoding.Base58.encode(hex('')),
    'base58 encode 00': (bsv) => bsv.encoding.Base58.encode(hex('00')),
    'base58 encode leading zeros': (bsv) => bsv.encoding.Base58.encode(hex('000000deadbeef')),
    'base58 encode ff': (bsv) => bsv.encoding.Base58.encode(hex('ff')),
    'base58 encode hello': (bsv) => bsv.encoding.Base58.encode(hex(BUFFERS.hello)),
    'base58 roundtrip leading zeros': (bsv) => {
      const b = hex('000000deadbeef')
      return bsv.encoding.Base58.decode(bsv.encoding.Base58.encode(b))
    },
    'base58 decode rejects invalid char 0': (bsv) => bsv.encoding.Base58.decode('0OIl'),
    'base58 decode empty string': (bsv) => bsv.encoding.Base58.decode(''),

    // --- Base58Check ---------------------------------------------------------
    'base58check encode p2pkh payload': (bsv) =>
      bsv.encoding.Base58Check.encode(hex('00' + '48b20e254c0677e760bab964aec16818d6b7134a')),
    'base58check decode known address': (bsv) =>
      bsv.encoding.Base58Check.decode(ADDRESSES.mainnetP2PKH),
    'base58check rejects bad checksum': (bsv) =>
      bsv.encoding.Base58Check.decode(ADDRESSES.badChecksum),
    'base58check validChecksum on good': (bsv) =>
      bsv.encoding.Base58Check.validChecksum(ADDRESSES.mainnetP2PKH),
    'base58check validChecksum on bad': (bsv) =>
      bsv.encoding.Base58Check.validChecksum(ADDRESSES.badChecksum),
    'base58check checksum of empty': (bsv) => bsv.encoding.Base58Check.checksum(hex('')),

    // --- Varint --------------------------------------------------------------
    // The 0xfc/0xfd, 0xffff/0x10000 and 0xffffffff/0x100000000 boundaries are
    // where varint encoders classically go wrong by one byte.
    ...BUFFERS.varintBoundaries.reduce((acc, n) => {
      acc[`varint fromNumber ${n}`] = (bsv) => new bsv.encoding.Varint().fromNumber(n).toBuffer()
      return acc
    }, {}),
    'varint roundtrip 252': (bsv) => new bsv.encoding.Varint(hex('fc')).toNumber(),
    'varint roundtrip 253': (bsv) => new bsv.encoding.Varint(hex('fdfd00')).toNumber(),
    'varint fromBN large': (bsv) =>
      new bsv.encoding.Varint().fromBN(new bsv.crypto.BN('18446744073709551615')).toBuffer(),
    'varint toBN of 8-byte': (bsv) =>
      new bsv.encoding.Varint(hex('ffffffffffffffffff')).toBN(),

    // --- BufferWriter --------------------------------------------------------
    'bufferwriter empty toBuffer': (bsv) => new bsv.encoding.BufferWriter().toBuffer(),
    'bufferwriter mixed widths': (bsv) => new bsv.encoding.BufferWriter()
      .writeUInt8(1)
      .writeUInt16BE(2)
      .writeUInt16LE(3)
      .writeUInt32BE(4)
      .writeUInt32LE(5)
      .writeInt32LE(-6)
      .toBuffer(),
    'bufferwriter writeReverse': (bsv) =>
      new bsv.encoding.BufferWriter().writeReverse(hex('01020304')).toBuffer(),
    'bufferwriter writeUInt64LEBN': (bsv) => new bsv.encoding.BufferWriter()
      .writeUInt64LEBN(new bsv.crypto.BN('4294967296')).toBuffer(),
    'bufferwriter writeUInt64BEBN': (bsv) => new bsv.encoding.BufferWriter()
      .writeUInt64BEBN(new bsv.crypto.BN('4294967296')).toBuffer(),
    'bufferwriter writeVarintNum boundaries': (bsv) => {
      const w = new bsv.encoding.BufferWriter()
      BUFFERS.varintBoundaries.forEach((n) => w.writeVarintNum(n))
      return w.toBuffer()
    },
    'bufferwriter writeUInt8 overflow 256': (bsv) =>
      new bsv.encoding.BufferWriter().writeUInt8(256).toBuffer(),
    'bufferwriter writeUInt8 negative': (bsv) =>
      new bsv.encoding.BufferWriter().writeUInt8(-1).toBuffer(),

    // --- BufferReader --------------------------------------------------------
    'bufferreader reads to eof': (bsv) => {
      const r = new bsv.encoding.BufferReader(hex('0102030405'))
      return { a: r.readUInt8(), b: r.readUInt32BE(), eof: r.eof(), finished: r.finished() }
    },
    'bufferreader read past end': (bsv) =>
      new bsv.encoding.BufferReader(hex('01')).readUInt32BE(),
    'bufferreader readReverse': (bsv) =>
      new bsv.encoding.BufferReader(hex('01020304')).readReverse(),
    'bufferreader readVarLengthBuffer truncated': (bsv) =>
      new bsv.encoding.BufferReader(hex('ff01')).readVarLengthBuffer(),
    'bufferreader readVarintNum 8-byte overflows safe int': (bsv) =>
      new bsv.encoding.BufferReader(hex('ffffffffffffffffff')).readVarintNum(),
    'bufferreader readVarintBN 8-byte': (bsv) =>
      new bsv.encoding.BufferReader(hex('ffffffffffffffffff')).readVarintBN(),
    'bufferreader readAll on empty': (bsv) =>
      new bsv.encoding.BufferReader(hex('')).readAll(),

    // --- Round-trip invariants ----------------------------------------------
    'script hex roundtrip p2pkh': (bsv) =>
      bsv.Script.fromHex(SCRIPTS.p2pkh).toHex() === SCRIPTS.p2pkh,
    'base58check roundtrip all sample addresses': (bsv) =>
      [ADDRESSES.mainnetP2PKH, ADDRESSES.mainnetP2SH, ADDRESSES.testnetP2PKH]
        .map((a) => bsv.encoding.Base58Check.encode(bsv.encoding.Base58Check.decode(a)) === a)
  }
}
