'use strict'

const { BIP32 } = require('../vectors')

const cases = {}

// Full BIP32 derivation across all three published seeds and every path.
// Vector 3 exists precisely to catch implementations that strip leading zero
// bytes from a derived key, so it is not optional coverage.
for (const [seedName, seedHex] of [['seed1', BIP32.seed1], ['seed2', BIP32.seed2], ['seed3', BIP32.seed3]]) {
  cases[`${seedName} master`] = (bsv) => {
    const hd = bsv.HDPrivateKey.fromSeed(Buffer.from(seedHex, 'hex'))
    return { xprv: hd.toString(), xpub: hd.hdPublicKey.toString() }
  }

  for (const path of BIP32.paths) {
    cases[`${seedName} derive ${path}`] = (bsv) => {
      const hd = bsv.HDPrivateKey.fromSeed(Buffer.from(seedHex, 'hex')).deriveChild(path)
      return {
        xprv: hd.toString(),
        xpub: hd.hdPublicKey.toString(),
        privkey: hd.privateKey.toWIF(),
        address: hd.privateKey.toAddress().toString(),
        depth: hd.depth,
        index: hd.childIndex,
        fingerprint: hd.fingerprint,
        chainCode: hd.chainCode
      }
    }
  }
}

Object.assign(cases, {
  // Public derivation must agree with private derivation for non-hardened paths.
  'public derivation matches private (m/0)': (bsv) => {
    const hd = bsv.HDPrivateKey.fromSeed(Buffer.from(BIP32.seed1, 'hex'))
    const fromPriv = hd.deriveChild('m/0').hdPublicKey.toString()
    const fromPub = hd.hdPublicKey.deriveChild('m/0').toString()
    return { fromPriv, fromPub, match: fromPriv === fromPub }
  },
  // Hardened derivation from a public key is mathematically impossible and
  // must fail loudly rather than return a wrong key.
  'hardened derivation from xpub is rejected': (bsv) =>
    bsv.HDPrivateKey.fromSeed(Buffer.from(BIP32.seed1, 'hex')).hdPublicKey.deriveChild("m/0'"),

  'xprv parse round-trips': (bsv) => bsv.HDPrivateKey.fromString(BIP32.xprv).toString(),
  'xpub parse round-trips': (bsv) => bsv.HDPublicKey.fromString(BIP32.xpub).toString(),
  'xprv toObject': (bsv) => bsv.HDPrivateKey.fromString(BIP32.xprv).toObject(),

  'xprv with bad checksum rejected': (bsv) =>
    bsv.HDPrivateKey.fromString(BIP32.xprv.slice(0, -1) + 'X'),
  'xpub parsed as xprv rejected': (bsv) => bsv.HDPrivateKey.fromString(BIP32.xpub),
  'xprv parsed as xpub rejected': (bsv) => bsv.HDPublicKey.fromString(BIP32.xprv),
  'seed too short rejected': (bsv) => bsv.HDPrivateKey.fromSeed(Buffer.alloc(8, 1)),
  'seed too long rejected': (bsv) => bsv.HDPrivateKey.fromSeed(Buffer.alloc(129, 1)),
  'garbage path rejected': (bsv) =>
    bsv.HDPrivateKey.fromString(BIP32.xprv).deriveChild('not/a/path'),
  // Index at and beyond the hardened boundary.
  'derive index 0x7fffffff': (bsv) =>
    bsv.HDPrivateKey.fromString(BIP32.xprv).deriveChild(2147483647).toString(),
  'derive index 0x80000000 (hardened via number)': (bsv) =>
    bsv.HDPrivateKey.fromString(BIP32.xprv).deriveChild(2147483648).toString(),
  'derive negative index rejected': (bsv) =>
    bsv.HDPrivateKey.fromString(BIP32.xprv).deriveChild(-1)
})

module.exports = { name: 'hdkeys', cases }
