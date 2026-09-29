'use strict'

/* global describe, it */

// The breadth behind test/spv/declared_target.js: where that file shows the headline cases,
// this one sweeps the edges.
//
// 1. `targetFromBits` against a transcription of the node's own rules — arith_uint256::
//    SetCompact (arith_uint256.cpp) and the range checks of CheckProofOfWork (pow.cpp) in
//    bitcoin-sv — over every size 0..40 crossed with edge words, plus a seeded sweep. The
//    first version of the port tested the raw word for zero before shifting, so 410 of
//    200,533 values (all sizes 0..2) gave a target of 0 where the node refuses the bits.
// 2. Every loose input the policy parsers must refuse. bn.js reads `1e21` as 23521 and
//    `'4.3e9'` as 4, and parseInt reads '1d00ffzz' as 0x1d00ff: a floor or a limit that
//    silently becomes something else fails open.
// 3. verifyHeaderChain builds its headers from 80 bytes or not at all.

const expect = require('chai').expect
const BN = require('../../dist/crypto/bn')
const BlockHeader = require('../../dist/block/blockheader')
const merkleproof = require('../../dist/spv/merkleproof')
const headerchain = require('../../dist/spv/headerchain')

const GENESIS =
  '01000000' + '00'.repeat(32) +
  '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a' +
  '29ab5f49' + 'ffff001d' + '1dac2b7c'
const GENESIS_TXID = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'

// SetCompact, then CheckProofOfWork's range test minus the powLimit comparison. Kept line
// for line with the C++ so a reader can hold the two side by side; note that nWord is
// shifted BEFORE the negative, overflow and zero tests read it.
function nodeTarget (nCompact) {
  const nSize = nCompact >>> 24
  let nWord = nCompact & 0x007fffff
  let bn
  if (nSize <= 3) {
    nWord = nWord >>> (8 * (3 - nSize))
    bn = new BN(nWord)
  } else {
    bn = new BN(nWord).shln(8 * (nSize - 3)).maskn(256)
  }
  const fNegative = nWord !== 0 && (nCompact & 0x00800000) !== 0
  const fOverflow = nWord !== 0 && ((nSize > 34) ||
    (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))
  if (fNegative || bn.isZero() || fOverflow) return null
  return bn
}

// xorshift32, seeded, so a failing value is the same value on every run.
function xorshift32 (seed) {
  let x = seed >>> 0
  return function () {
    x ^= x << 13; x >>>= 0
    x ^= x >>> 17
    x ^= x << 5; x >>>= 0
    return x
  }
}

function bitsCases () {
  const words = [0, 1, 0x12, 0x7f, 0x80, 0xff, 0x100, 0x1234, 0x3456, 0x7fff, 0x8000, 0xffff,
    0x10000, 0x12345, 0x7fffff, 0x800000, 0x800001, 0x80ffff, 0xffffff]
  const cases = []
  for (let size = 0; size <= 40; size++) {
    words.forEach(function (w) { cases.push(((size << 24) | w) >>> 0) })
  }
  // Named cases: mainnet/testnet limit, regtest, the forgery, and the sizes where the
  // shifted word decides.
  cases.push(0x1d00ffff, 0x207fffff, 0x2100ffff, 0x01003456, 0x00ffffff, 0x02000001,
    0x0200ffff, 0x01800001, 0x02800100, 0x03800000, 0x04800000, 0xffffffff)
  const next = xorshift32(0x5eed5eed)
  for (let i = 0; i < 100000; i++) cases.push(next())
  // Random words at the sizes a real header can declare, where the sweep above is thin.
  for (let j = 0; j < 20000; j++) {
    const s = next() % 36
    cases.push(((s << 24) | (next() & 0xffffff)) >>> 0)
  }
  return cases
}

function hex8 (n) { return '0x' + ('00000000' + n.toString(16)).slice(-8) }

// JSON.stringify prints NaN and Infinity as null, which would name the wrong case.
function show (v) { return typeof v === 'number' ? String(v) : JSON.stringify(v) }

describe('SPV declared target — edges', function () {
  describe('targetFromBits agrees with the node\'s SetCompact + CheckProofOfWork', function () {
    it('on every size 0..40 crossed with edge words, and a seeded sweep', function () {
      const cases = bitsCases()
      const mismatches = []
      cases.forEach(function (bits) {
        const ours = merkleproof.targetFromBits(bits)
        const node = nodeTarget(bits)
        const same = (ours === null && node === null) ||
          (ours !== null && node !== null && ours.eq(node))
        if (!same) {
          mismatches.push(hex8(bits) + ': ours ' + (ours === null ? 'null' : ours.toString(16)) +
            ', node ' + (node === null ? 'null' : node.toString(16)))
        }
      })
      expect(cases.length).to.be.above(120000)
      expect(mismatches, mismatches.slice(0, 10).join('; ')).to.deep.equal([])
    })

    it('refuses a small size whose shifted word is zero, as the node does', function () {
      [0x01003456, 0x00ffffff, 0x02000001, 0x01000001, 0x00000001].forEach(function (bits) {
        expect(merkleproof.targetFromBits(bits), hex8(bits)).to.equal(null)
      })
      expect(merkleproof.targetFromBits(0x0200ffff).toString(16)).to.equal('ff')
    })

    it('never reports work for a target it refused', function () {
      bitsCases().slice(0, 2000).forEach(function (bits) {
        const t = merkleproof.targetFromBits(bits)
        if (t === null) return
        expect(t.isZero(), hex8(bits)).to.equal(false)
        expect(merkleproof.workFromTarget(t).cmp(merkleproof.workFromTarget(new BN(1))) <= 0,
          hex8(bits)).to.equal(true)
      })
    })

    it('gives difficulty 1 the genesis block\'s chainwork, 0x100010001', function () {
      const work = merkleproof.workFromTarget(merkleproof.targetFromBits(0x1d00ffff))
      expect(work.toString(16)).to.equal('100010001')
      // The node's form, (~t / (t + 1)) + 1 over 256 bits, is the same number.
      const t = merkleproof.targetFromBits(0x1d00ffff)
      const notT = new BN(1).shln(256).subn(1).sub(t)
      expect(notT.div(t.addn(1)).addn(1).eq(work)).to.equal(true)
    })
  })

  describe('policy inputs refuse anything read loosely', function () {
    function inclusion (extra) {
      const params = { header: GENESIS, txid: GENESIS_TXID, index: 0, nodes: [] }
      Object.keys(extra).forEach(function (k) { params[k] = extra[k] })
      return merkleproof.verifyTxInclusion(params)
    }

    // Each with what a lenient parser would have made of it.
    const BAD_MIN_WORK = [
      [1e21, 'bn.js reads "1e+21" as 23521'],
      ['4.3e9', 'truncation at "." gave 4'],
      [4.5, 'not an integer'],
      ['abc', 'bn.js reads it as 1122'],
      ['0x10', 'bn.js reads it as 3310'],
      ['', 'empty'],
      [' 5', 'whitespace'],
      ['-5', 'negative string'],
      [-5, 'negative number'],
      [Number.MAX_SAFE_INTEGER + 2, 'beyond the safe integers'],
      [NaN, 'NaN'],
      [Infinity, 'Infinity'],
      [{}, 'an object'],
      [[], 'an array'],
      [true, 'a boolean']
    ]

    BAD_MIN_WORK.forEach(function (c) {
      it('minWork ' + show(c[0]) + ' throws (' + c[1] + ')', function () {
        expect(function () { inclusion({ minWork: c[0] }) },
          'minWork ' + String(c[0])).to.throw(/minWork/)
      })
    })

    it('minWork accepts a safe integer, a decimal string and a BN, and compares exactly', function () {
      expect(inclusion({ minWork: 4295032833 }).workSufficient).to.equal(true)
      expect(inclusion({ minWork: '4295032833' }).workSufficient).to.equal(true)
      expect(inclusion({ minWork: new BN('4295032833', 10) }).workSufficient).to.equal(true)
      expect(inclusion({ minWork: 0 }).workSufficient).to.equal(true)
      expect(inclusion({ minWork: '4295032834' }).workSufficient).to.equal(false)
      expect(inclusion({ minWork: '100000000000000000000000' }).valid).to.equal(false)
    })

    const BAD_POW_LIMIT = [
      ['1d00ffzz', 'parseInt gave 0x1d00ff'],
      ['1d00ffffZZ', 'parseInt gave 0x1d00ffff'],
      ['0x', 'no digits'],
      ['', 'empty'],
      ['1d00ffff0', 'nine hex digits'],
      [-1, 'negative'],
      [1.5, 'not an integer'],
      [0x1ffffffff, 'wider than uint32'],
      [NaN, 'NaN'],
      [{}, 'an object'],
      [true, 'a boolean'],
      [0x00000000, 'a zero target'],
      [0x01003456, 'a shifted-to-zero target'],
      [0x1d80ffff, 'a negative target'],
      [0x2301ffff, 'an overflowing target']
    ]

    BAD_POW_LIMIT.forEach(function (c) {
      it('powLimit ' + show(c[0]) + ' throws (' + c[1] + ')', function () {
        expect(function () { merkleproof.targetLimit(c[0]) },
          'powLimit ' + String(c[0])).to.throw(/powLimit/)
        expect(function () { inclusion({ powLimit: c[0] }) },
          'powLimit ' + String(c[0]) + ' via verifyTxInclusion').to.throw(/powLimit/)
      })
    })

    it('powLimit accepts hex with or without 0x, a uint32 and a BN, all the same limit', function () {
      const expected = merkleproof.targetFromBits(0x1d00ffff)
      ;['1d00ffff', '0x1d00ffff', '1D00FFFF', 0x1d00ffff, expected, undefined, null]
        .forEach(function (p) {
          expect(merkleproof.targetLimit(p).eq(expected), String(p)).to.equal(true)
        })
    })

    it('requirePow:false reads neither policy input, so neither can throw', function () {
      expect(inclusion({ requirePow: false, powLimit: '1d00ffzz', minWork: 1e21 }).valid)
        .to.equal(true)
    })
  })

  describe('verifyHeaderChain takes headers as 80 bytes or not at all', function () {
    const genesis = Buffer.from(GENESIS, 'hex')

    it('refuses an object that only claims validProofOfWork', function () {
      const claim = {
        bits: 0x1d00ffff,
        prevHash: Buffer.alloc(32),
        id: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
        validProofOfWork: function () { return true },
        getDifficulty: function () { return 1 }
      }
      expect(function () { headerchain.verifyHeaderChain([claim]) }).to.throw(/80 bytes/)
      expect(function () { headerchain.verifyHeaderChain([genesis, claim]) }).to.throw(/80 bytes/)
    })

    it('refuses a Buffer of 79 or 81 bytes', function () {
      expect(function () { headerchain.verifyHeaderChain([genesis.slice(0, 79)]) })
        .to.throw(/80 bytes/)
      expect(function () { headerchain.verifyHeaderChain([Buffer.concat([genesis, Buffer.alloc(1)])]) })
        .to.throw(/80 bytes/)
    })

    it('refuses hex that is short, long, or 80 good bytes followed by junk', function () {
      [GENESIS.slice(0, 158), GENESIS + '00', GENESIS + 'zz', GENESIS.slice(0, 159) + 'g']
        .forEach(function (h) {
          expect(function () { headerchain.verifyHeaderChain([h]) }, h.length + ' chars')
            .to.throw(/160 hex|80 bytes/)
        })
    })

    it('accepts the genesis header as a Buffer, as hex, and as a BlockHeader', function () {
      [genesis, GENESIS, BlockHeader.fromBuffer(genesis)].forEach(function (h) {
        expect(headerchain.verifyHeaderChain([h]).valid).to.equal(true)
      })
    })
  })
})
