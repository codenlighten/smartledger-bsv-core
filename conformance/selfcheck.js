'use strict'

// Validate the *published* vectors in vectors.js against the library.
//
// Rationale: a conformance corpus is only as trustworthy as its inputs. If a
// constant in vectors.js were fabricated or mis-transcribed, every fixture
// derived from it would faithfully record the wrong thing and the corpus would
// certify a bug as correct behavior. So before any fixture is written, the
// vectors that have an independent published source must reproduce exactly.
//
// This is deliberately a hard gate, not a warning. A disagreement means either
// the vector is wrong or the library is wrong; both require a human.

const { BIP32, BIP39, TXS, ADDRESSES, KEYS } = require('./vectors')

// A check that throws is a failed check, not a crashed run: when verifying a
// half-finished rewrite, most checks will throw, and the report is the point.
function check (results, label, actualFn, expected) {
  let actual
  try {
    actual = typeof actualFn === 'function' ? actualFn() : actualFn
  } catch (err) {
    results.push({ label, ok: false, actual: `threw ${err.name}: ${err.message}`, expected })
    return
  }
  results.push({ label, ok: actual === expected, actual, expected })
}

function run (bsv) {
  const results = []

  // BIP39 (Trezor reference vectors, passphrase "TREZOR")
  for (const e of BIP39.entries) {
    const words = e.mnemonic.split(' ').length
    check(
      results,
      `BIP39 ${words}-word "${e.mnemonic.split(' ')[0]}..." -> seed`,
      () => bsv.Mnemonic.fromString(e.mnemonic).toSeed(BIP39.passphrase).toString('hex'),
      e.seed
    )
    check(results, `BIP39 ${words}-word mnemonic is valid`,
      () => bsv.Mnemonic.isValid(e.mnemonic), true)
  }

  // BIP32 test vector 1
  const hd = bsv.HDPrivateKey.fromSeed(Buffer.from(BIP32.seed1, 'hex'))
  check(results, 'BIP32 vector1 m xprv', () => hd.toString(), BIP32.xprv)
  check(results, 'BIP32 vector1 m xpub', () => hd.hdPublicKey.toString(), BIP32.xpub)

  // key = 1 -> address, the strongest externally-checkable anchor for the
  // pubkey -> hash160 -> base58check path.
  check(results, 'secret key 1 (compressed) -> address',
    () => bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).toAddress().toString(),
    ADDRESSES.keyOneCompressed)
  check(results, 'secret key 1 (uncompressed) -> address',
    () => bsv.PrivateKey.fromWIF(KEYS.oneWIFUncompressed).toAddress().toString(),
    ADDRESSES.keyOneUncompressed)
  check(results, 'secret key 1 WIF round-trips',
    () => bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).toWIF(),
    KEYS.oneWIFCompressed)
  // NOTE: PrivateKey#toString() returns the WIF, not the hex — hence toHex().
  // Flagged for the API redesign: a default toString() that emits secret key
  // material in its most directly spendable form is an easy way to leak a key
  // into a log line.
  check(results, 'secret key 1 hex matches WIF',
    () => bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).toHex(),
    KEYS.oneHex)

  // Real transactions must round-trip byte-for-byte.
  for (const [name, raw] of Object.entries(TXS)) {
    check(results, `tx ${name} round-trips`, () => new bsv.Transaction(raw).toString(), raw)
  }

  // Addresses must survive a decode/encode cycle unchanged.
  for (const name of ['mainnetP2PKH', 'mainnetP2SH', 'testnetP2PKH']) {
    check(results, `address ${name} round-trips`,
      () => bsv.Address.fromString(ADDRESSES[name]).toString(), ADDRESSES[name])
  }

  // Malformed addresses must be rejected, not silently coerced.
  for (const name of ['badChecksum', 'tooShort', 'invalidChars']) {
    check(results, `address ${name} is rejected`, () => {
      try { bsv.Address.fromString(ADDRESSES[name]) } catch (_) { return true }
      return false
    }, true)
  }

  return results
}

module.exports = { run }
