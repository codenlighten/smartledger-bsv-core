'use strict'

const { KEYS, ADDRESSES } = require('../vectors')

const hex = (s) => Buffer.from(s, 'hex')

module.exports = {
  name: 'keys',
  cases: {
    // --- PrivateKey construction --------------------------------------------
    'privkey from WIF compressed': (bsv) => {
      const k = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      return { wif: k.toWIF(), hex: k.toHex(), compressed: k.compressed, network: k.network.name }
    },
    'privkey from WIF uncompressed': (bsv) => {
      const k = bsv.PrivateKey.fromWIF(KEYS.mainnetUncompressed)
      return { wif: k.toWIF(), hex: k.toHex(), compressed: k.compressed, network: k.network.name }
    },
    'privkey from WIF testnet': (bsv) => {
      const k = bsv.PrivateKey.fromWIF(KEYS.testnetCompressed)
      return { wif: k.toWIF(), address: k.toAddress().toString(), network: k.network.name }
    },
    'privkey from hex': (bsv) => bsv.PrivateKey.fromHex(KEYS.oneHex).toWIF(),
    'privkey toObject': (bsv) => bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed).toObject(),
    'privkey toString is WIF not hex': (bsv) =>
      bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed).toString(),
    'privkey inspect redacts nothing (documented behavior)': (bsv) =>
      bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed).inspect(),

    // --- PrivateKey boundary conditions -------------------------------------
    // n-1 is the largest valid secret; 0 and n are both invalid. An
    // implementation that accepts either produces an unusable or forgeable key.
    'privkey at n-1 is accepted': (bsv) => bsv.PrivateKey.fromHex(KEYS.maxValidHex).toWIF(),
    'privkey at n is rejected': (bsv) => bsv.PrivateKey.fromHex(KEYS.orderHex),
    'privkey at zero is rejected': (bsv) => bsv.PrivateKey.fromHex(KEYS.zeroHex),
    'privkey from short buffer rejected': (bsv) => bsv.PrivateKey.fromBuffer(hex('0102')),
    'privkey from oversized buffer rejected': (bsv) =>
      bsv.PrivateKey.fromBuffer(Buffer.alloc(33, 1)),
    'privkey from malformed bn rejected': (bsv) =>
      new bsv.PrivateKey({ bn: 'not-a-bn', network: 'livenet', compressed: true }),
    'privkey WIF with bad checksum rejected': (bsv) =>
      bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed.slice(0, -1) + 'X'),
    'privkey getValidationError on n': (bsv) => bsv.PrivateKey.getValidationError(KEYS.orderHex),
    'privkey isValid on n': (bsv) => bsv.PrivateKey.isValid(KEYS.orderHex),
    'privkey isValid on good WIF': (bsv) => bsv.PrivateKey.isValid(KEYS.mainnetCompressed),

    // --- PublicKey ----------------------------------------------------------
    'pubkey from privkey compressed': (bsv) => {
      const p = bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey
      return { hex: p.toString(), compressed: p.compressed }
    },
    'pubkey from privkey uncompressed': (bsv) => {
      const p = bsv.PrivateKey.fromWIF(KEYS.oneWIFUncompressed).publicKey
      return { hex: p.toString(), compressed: p.compressed }
    },
    'pubkey compressed<->uncompressed same point': (bsv) => {
      const c = bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey
      const u = bsv.PrivateKey.fromWIF(KEYS.oneWIFUncompressed).publicKey
      return { xMatch: c.point.getX().toString() === u.point.getX().toString() }
    },
    'pubkey fromX even': (bsv) =>
      bsv.PublicKey.fromX(false, bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey.point.getX()).toString(),
    'pubkey fromX odd': (bsv) =>
      bsv.PublicKey.fromX(true, bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey.point.getX()).toString(),
    'pubkey rejects point not on curve': (bsv) =>
      bsv.PublicKey.fromString('04' + '00'.repeat(64)),
    'pubkey rejects infinity': (bsv) => bsv.PublicKey.fromString('00'),
    'pubkey rejects truncated compressed': (bsv) => bsv.PublicKey.fromString('02' + '00'.repeat(31)),
    'pubkey rejects bad prefix': (bsv) => bsv.PublicKey.fromString('05' + '00'.repeat(32)),
    'pubkey isValid on garbage': (bsv) => bsv.PublicKey.isValid('deadbeef'),
    'pubkey toObject': (bsv) =>
      bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey.toObject(),

    // --- Addresses ----------------------------------------------------------
    'address key=1 compressed': (bsv) =>
      bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).toAddress().toString(),
    'address key=1 uncompressed': (bsv) =>
      bsv.PrivateKey.fromWIF(KEYS.oneWIFUncompressed).toAddress().toString(),
    'address from string p2pkh': (bsv) => {
      const a = bsv.Address.fromString(ADDRESSES.mainnetP2PKH)
      return { str: a.toString(), type: a.type, network: a.network.name, hash: a.hashBuffer }
    },
    'address from string p2sh': (bsv) => {
      const a = bsv.Address.fromString(ADDRESSES.mainnetP2SH)
      return { str: a.toString(), type: a.type, network: a.network.name }
    },
    'address testnet': (bsv) => {
      const a = bsv.Address.fromString(ADDRESSES.testnetP2PKH)
      return { str: a.toString(), type: a.type, network: a.network.name }
    },
    'address rejects bad checksum': (bsv) => bsv.Address.fromString(ADDRESSES.badChecksum),
    'address rejects too short': (bsv) => bsv.Address.fromString(ADDRESSES.tooShort),
    'address rejects invalid chars': (bsv) => bsv.Address.fromString(ADDRESSES.invalidChars),
    'address rejects empty string': (bsv) => bsv.Address.fromString(''),
    // Cross-network confusion is a fund-loss bug: a testnet address must not
    // validate as livenet.
    'address testnet string parsed as livenet': (bsv) =>
      bsv.Address.fromString(ADDRESSES.testnetP2PKH, 'livenet'),
    'address livenet string parsed as testnet': (bsv) =>
      bsv.Address.fromString(ADDRESSES.mainnetP2PKH, 'testnet'),
    'address getValidationError bad': (bsv) =>
      bsv.Address.getValidationError(ADDRESSES.badChecksum),
    'address isValid good': (bsv) => bsv.Address.isValid(ADDRESSES.mainnetP2PKH),
    'address toObject': (bsv) => bsv.Address.fromString(ADDRESSES.mainnetP2PKH).toObject()
  }
}
