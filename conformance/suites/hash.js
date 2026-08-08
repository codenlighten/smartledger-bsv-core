'use strict'

const { BUFFERS } = require('../vectors')

const hex = (s) => Buffer.from(s, 'hex')
const utf8 = (s) => Buffer.from(s, 'utf8')

// Inputs chosen to straddle every block boundary that matters: empty, one byte,
// 55/56 bytes (SHA-256 padding boundary), 63/64/65 (block size), and 119/120
// (SHA-512 padding boundary).
const SIZES = [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1000]

const ALGOS = ['sha1', 'sha256', 'sha256sha256', 'ripemd160', 'sha256ripemd160', 'sha512']

const cases = {}

for (const algo of ALGOS) {
  cases[`${algo} of empty`] = (bsv) => bsv.crypto.Hash[algo](hex(''))
  cases[`${algo} of "abc"`] = (bsv) => bsv.crypto.Hash[algo](utf8('abc'))
  cases[`${algo} of "hello"`] = (bsv) => bsv.crypto.Hash[algo](hex(BUFFERS.hello))
  cases[`${algo} across block boundaries`] = (bsv) =>
    SIZES.map((n) => bsv.crypto.Hash[algo](Buffer.alloc(n, 0xab)).toString('hex'))
  // Type discipline: hashing a string rather than a Buffer must be rejected,
  // not silently coerced — silent coercion has produced wrong-digest bugs.
  cases[`${algo} rejects a string argument`] = (bsv) => bsv.crypto.Hash[algo]('abc')
  cases[`${algo} rejects null`] = (bsv) => bsv.crypto.Hash[algo](null)
}

// --- HMAC ---------------------------------------------------------------
// RFC 4231 case 2: key "Jefe", data "what do ya want for nothing?".
cases['sha256hmac rfc4231 case2'] = (bsv) =>
  bsv.crypto.Hash.sha256hmac(utf8('what do ya want for nothing?'), utf8('Jefe'))
cases['sha512hmac rfc4231 case2'] = (bsv) =>
  bsv.crypto.Hash.sha512hmac(utf8('what do ya want for nothing?'), utf8('Jefe'))
cases['sha256hmac empty key and data'] = (bsv) =>
  bsv.crypto.Hash.sha256hmac(hex(''), hex(''))
// Key longer than the block size must be hashed down first.
cases['sha256hmac oversized key'] = (bsv) =>
  bsv.crypto.Hash.sha256hmac(utf8('data'), Buffer.alloc(200, 0xaa))
cases['sha512hmac oversized key'] = (bsv) =>
  bsv.crypto.Hash.sha512hmac(utf8('data'), Buffer.alloc(300, 0xaa))
cases['hmac rejects string key'] = (bsv) =>
  bsv.crypto.Hash.sha256hmac(utf8('data'), 'stringkey')

module.exports = { name: 'hash', cases }
