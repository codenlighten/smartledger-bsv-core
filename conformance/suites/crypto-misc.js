'use strict'

const { KEYS, BUFFERS } = require('../vectors')

const hex = (s) => Buffer.from(s, 'hex')
const utf8 = (s) => Buffer.from(s, 'utf8')

module.exports = {
  name: 'crypto-misc',
  cases: {
    // --- BN -----------------------------------------------------------------
    'BN from number': (bsv) => new bsv.crypto.BN(12345).toString(),
    'BN from hex': (bsv) => bsv.crypto.BN.fromHex('deadbeef').toString(),
    'BN toBuffer sized': (bsv) => new bsv.crypto.BN(1).toBuffer({ size: 32 }),
    'BN toBuffer natural': (bsv) => new bsv.crypto.BN(258).toBuffer(),
    'BN constants': (bsv) => ({
      zero: bsv.crypto.BN.Zero.toString(),
      one: bsv.crypto.BN.One.toString(),
      minus1: bsv.crypto.BN.Minus1.toString()
    }),
    // Script numbers are sign-magnitude little-endian, not two's complement.
    // Every boundary here is a known source of interpreter bugs.
    'BN script num round-trip': (bsv) => {
      const vals = [0, 1, -1, 127, -127, 128, -128, 255, -255, 256, -256, 32767, -32767, 2147483647, -2147483647]
      return vals.map((n) => {
        const b = new bsv.crypto.BN(n).toScriptNumBuffer()
        return { n, buf: b.toString('hex'), back: bsv.crypto.BN.fromScriptNumBuffer(b).toString() }
      })
    },
    'BN fromSM / toSM': (bsv) => {
      const vals = ['00', '01', '81', '0080', 'ff', '8000']
      return vals.map((h) => ({ h, sm: bsv.crypto.BN.fromSM(hex(h)).toString() }))
    },
    'BN fromScriptNumBuffer non-minimal with require flag': (bsv) =>
      bsv.crypto.BN.fromScriptNumBuffer(hex('0100'), true).toString(),
    'BN fromBuffer oversized': (bsv) => bsv.crypto.BN.fromBuffer(Buffer.alloc(40, 0xff)).toString(),

    // --- Point --------------------------------------------------------------
    'Point G coordinates': (bsv) => {
      const G = bsv.crypto.Point.getG()
      return { x: G.getX().toString(16), y: G.getY().toString(16) }
    },
    'Point N and validation': (bsv) => ({
      n: bsv.crypto.Point.getN().toString(16),
      gValid: (() => { try { bsv.crypto.Point.getG().validate(); return true } catch (e) { return e.message } })()
    }),
    'Point from invalid coordinates rejected': (bsv) =>
      bsv.crypto.Point.fromX(false, new bsv.crypto.BN(0)),
    'Point scalar multiply by 2': (bsv) =>
      bsv.crypto.Point.getG().mul(new bsv.crypto.BN(2)).getX().toString(16),

    // --- Random -------------------------------------------------------------
    // We cannot pin random output, but we can pin its shape and that repeated
    // draws differ — a broken RNG returning a constant is catastrophic.
    'Random getRandomBuffer shape': (bsv) => {
      const a = bsv.crypto.Random.getRandomBuffer(32)
      const b = bsv.crypto.Random.getRandomBuffer(32)
      return { length: a.length, isBuffer: Buffer.isBuffer(a), differs: !a.equals(b) }
    },
    'Random zero length': (bsv) => bsv.crypto.Random.getRandomBuffer(0).length,

    // --- ECIES --------------------------------------------------------------
    // Both keys fixed, so the ECDH secret (and therefore IV and ciphertext) is
    // deterministic. The ephemeral-key path is exercised only for shape.
    'ecies encrypt fixed keys': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      return new bsv.ECIES().privateKey(a).publicKey(b.publicKey).encrypt('hello world')
    },
    'ecies round-trip': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      const ct = new bsv.ECIES().privateKey(a).publicKey(b.publicKey).encrypt('hello world')
      const pt = new bsv.ECIES().privateKey(b).publicKey(a.publicKey).decrypt(ct)
      return pt.toString()
    },
    'ecies empty message': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      return new bsv.ECIES().privateKey(a).publicKey(b.publicKey).encrypt('')
    },
    'ecies long message': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      return new bsv.ECIES().privateKey(a).publicKey(b.publicKey).encrypt(hex(BUFFERS.long520))
    },
    // Tampering with the ciphertext must fail the MAC, not return garbage.
    'ecies rejects tampered ciphertext': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      const ct = new bsv.ECIES().privateKey(a).publicKey(b.publicKey).encrypt('hello world')
      ct[ct.length - 1] ^= 0xff
      return new bsv.ECIES().privateKey(b).publicKey(a.publicKey).decrypt(ct)
    },
    'ecies rejects wrong key': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      const c = bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed)
      const ct = new bsv.ECIES().privateKey(a).publicKey(b.publicKey).encrypt('hello world')
      return new bsv.ECIES().privateKey(c).publicKey(a.publicKey).decrypt(ct)
    },
    'ecies truncated ciphertext': (bsv) => {
      const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2)
      return new bsv.ECIES().privateKey(b).publicKey(a.publicKey).decrypt(hex('0102'))
    },

    // --- Message signing ------------------------------------------------------
    'message magicHash': (bsv) => new bsv.Message('hello').magicHash(),
    'message sign deterministic': (bsv) => {
      const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const m = new bsv.Message('hello')
      const first = m.sign(key)
      const second = m.sign(key)
      return { sig: first, stable: first === second }
    },
    'message verify round-trip': (bsv) => {
      const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const m = new bsv.Message('hello')
      const sig = m.sign(key)
      return {
        good: m.verify(key.toAddress(), sig),
        wrongAddress: m.verify(bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2).toAddress(), sig),
        wrongMessage: new bsv.Message('goodbye').verify(key.toAddress(), sig)
      }
    },
    'message empty string': (bsv) => {
      const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      return new bsv.Message('').sign(key)
    },
    'message unicode': (bsv) => {
      const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      const m = new bsv.Message('héllo wörld 🌍')
      return { hash: m.magicHash(), sig: m.sign(key) }
    },
    'message verify garbage signature': (bsv) => {
      const key = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed)
      return new bsv.Message('hello').verify(key.toAddress(), 'not-a-signature')
    },

    // --- Shamir ---------------------------------------------------------------
    // Shamir.split(secret, threshold, shares, options). Splitting is randomized,
    // so we pin the recovery invariant and share shape rather than share bytes.
    'shamir split shape': (bsv) => {
      const shares = bsv.Shamir.split(hex(KEYS.oneHex), 2, 3)
      return { count: shares.length, keys: Object.keys(shares[0]).sort() }
    },
    'shamir threshold shares recombine': (bsv) => {
      const secret = hex(KEYS.oneHex)
      const shares = bsv.Shamir.split(secret, 2, 3)
      return Buffer.from(bsv.Shamir.combine(shares.slice(0, 2))).toString('hex') === KEYS.oneHex
    },
    'shamir all shares recombine': (bsv) => {
      const shares = bsv.Shamir.split(hex(KEYS.oneHex), 2, 3)
      return Buffer.from(bsv.Shamir.combine(shares)).toString('hex') === KEYS.oneHex
    },
    'shamir below threshold does not recover': (bsv) => {
      const shares = bsv.Shamir.split(hex(KEYS.oneHex), 2, 3)
      try {
        return Buffer.from(bsv.Shamir.combine(shares.slice(0, 1))).toString('hex') === KEYS.oneHex
      } catch (err) {
        return 'threw:' + err.name
      }
    },
    'shamir threshold below 2 rejected': (bsv) => bsv.Shamir.split(hex(KEYS.oneHex), 1, 3),
    'shamir shares below threshold rejected': (bsv) => bsv.Shamir.split(hex(KEYS.oneHex), 3, 2),
    'shamir shares above 255 rejected': (bsv) => bsv.Shamir.split(hex(KEYS.oneHex), 2, 256),
    'shamir verifyShare on a real share': (bsv) => {
      const shares = bsv.Shamir.split(hex(KEYS.oneHex), 2, 3, { checksum: true })
      return bsv.Shamir.verifyShare(shares[0])
    },

    // --- Opcode ---------------------------------------------------------------
    'opcode map is complete': (bsv) => {
      const out = {}
      for (const [name, val] of Object.entries(bsv.Opcode.map)) out[name] = val
      return out
    },
    'opcode smallInt round-trip': (bsv) =>
      [0, 1, 2, 15, 16].map((n) => bsv.Opcode.smallInt(n).toString()),
    'opcode smallInt out of range': (bsv) => bsv.Opcode.smallInt(17),
    'opcode fromString unknown': (bsv) => bsv.Opcode.fromString('OP_NOPE'),
    'opcode isSmallIntOp': (bsv) =>
      [0x00, 0x51, 0x60, 0x61].map((n) => bsv.Opcode.isSmallIntOp(n)),

    // --- Mnemonic -------------------------------------------------------------
    'mnemonic from entropy': (bsv) =>
      bsv.Mnemonic.fromSeed(hex('00'.repeat(16)), bsv.Mnemonic.Words.ENGLISH).toString(),
    'mnemonic invalid checksum rejected': (bsv) =>
      bsv.Mnemonic.fromString('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon'),
    'mnemonic wrong word count rejected': (bsv) => bsv.Mnemonic.fromString('abandon abandon'),
    'mnemonic non-wordlist word rejected': (bsv) =>
      bsv.Mnemonic.fromString('zzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),
    'mnemonic toHDPrivateKey': (bsv) =>
      bsv.Mnemonic.fromString('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
        .toHDPrivateKey('TREZOR').toString(),
    'mnemonic isValid table': (bsv) => [
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
      'not a real mnemonic at all',
      ''
    ].map((m) => ({ m: m.slice(0, 30), valid: bsv.Mnemonic.isValid(m) })),

    // --- Hash-of-known-string sanity -----------------------------------------
    'hash160 of key=1 pubkey': (bsv) =>
      bsv.crypto.Hash.sha256ripemd160(
        bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey.toBuffer()
      ),
    'txid byte order is reversed hash': (bsv) => {
      const tx = new bsv.Transaction(require('../vectors').TXS.p2pkhSpend)
      return { id: tx.id, hash: tx.hash, reversed: tx.id === Buffer.from(tx.hash, 'hex').reverse().toString('hex') }
    },
    'sha256 of utf8 vs latin1 differ': (bsv) => ({
      utf8: bsv.crypto.Hash.sha256(utf8('café')).toString('hex'),
      latin1: bsv.crypto.Hash.sha256(Buffer.from('café', 'latin1')).toString('hex')
    })
  }
}
