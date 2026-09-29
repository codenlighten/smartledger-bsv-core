'use strict'

/* global describe, it */

// A header's proof of work is only as good as the target it declares — and it declares its
// own. `hash <= target` alone therefore proves nothing at all: with `bits` of 0x2100ffff
// every hash qualifies, so a valid-looking header costs one attempt to make. Until this
// change, NotaryHash.verify() returned valid for a certificate anchored in such a header
// with proof of work ENABLED, and verifyHeaderChain accepted a whole chain of them.
//
// The declared target is now capped at `powLimit`: difficulty 1 (0x1d00ffff), which is the
// proof-of-work limit of both mainnet and testnet. Regtest declares 0x207fffff and is only
// believed when a caller asks for that limit. `minWork` can demand more than the cap.
//
// Retargeting is still not validated, and no header check detects an orphan: a genuine block
// that lost a race carries real work. `blockHashAtHeight` is how a caller with its own chain
// view says which block that height really holds.
//
// Found while mirroring a hardening of the BRC-220 reference implementation.

require('chai').should()
const expect = require('chai').expect
const bsv = require('../..')
const SPV = bsv.SPV
const BlockHeader = bsv.BlockHeader

// The genesis block: a real header at exactly the proof-of-work limit, with one
// transaction, so its txid IS its Merkle root and the inclusion proof is empty.
const GENESIS =
  '01000000' + '00'.repeat(32) + // version, prevHash
  '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a' + // merkleRoot
  '29ab5f49' + 'ffff001d' + '1dac2b7c' // time, bits, nonce
const GENESIS_TXID = '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
const GENESIS_ID = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
const DIFFICULTY_1_WORK = '4295032833'

function genesisProof (extra) {
  const params = { header: GENESIS, txid: GENESIS_TXID, index: 0, nodes: [] }
  Object.keys(extra || {}).forEach(function (k) { params[k] = extra[k] })
  return SPV.verifyTxInclusion(params)
}

// Mine a header at whatever target it likes to declare, over the given Merkle root.
// Returns the header and how many nonces it took, which is the point of the test.
function mine (bits, merkleRootInternal, prevHashInternal) {
  for (let nonce = 0; nonce < 500000; nonce++) {
    const h = new BlockHeader({
      version: 1,
      prevHash: prevHashInternal || Buffer.alloc(32),
      merkleRoot: merkleRootInternal,
      time: 1231006505,
      bits,
      nonce
    })
    if (h.validProofOfWork()) return { header: h, tries: nonce + 1 }
  }
  throw new Error('could not mine at bits ' + bits.toString(16))
}

const genesisRootInternal = Buffer.from(GENESIS_TXID, 'hex').reverse()

describe('a header is not believed about its own difficulty', function () {
  describe('verifyTxInclusion', function () {
    it('accepts the genesis header, at exactly the proof-of-work limit', function () {
      const r = genesisProof()
      r.valid.should.equal(true)
      r.rootMatches.should.equal(true)
      r.powValid.should.equal(true)
      r.targetAllowed.should.equal(true)
      r.workSufficient.should.equal(true)
      r.work.should.equal(DIFFICULTY_1_WORK)
      r.blockHash.should.equal(GENESIS_ID)
    })

    it('refuses a header that declares an easy target, which costs nothing to mine', function () {
      const forged = mine(0x2100ffff, genesisRootInternal)
      // The whole problem, as a number: no work at all.
      forged.tries.should.equal(1)
      forged.header.validProofOfWork().should.equal(true)
      const r = genesisProof({ header: forged.header.toBuffer() })
      r.rootMatches.should.equal(true)
      r.powValid.should.equal(true, 'it does meet the target it chose')
      r.targetAllowed.should.equal(false)
      r.valid.should.equal(false)
      r.work.should.equal('1')
    })

    it('refuses every target easier than the limit, and none harder', function () {
      ;[0x1f00ffff, 0x2000ffff, 0x207fffff, 0x2100ffff].forEach(function (bits) {
        const m = mine(bits, genesisRootInternal)
        genesisProof({ header: m.header.toBuffer() }).targetAllowed
          .should.equal(false, 'bits 0x' + bits.toString(16))
      })
      genesisProof().targetAllowed.should.equal(true)
    })

    it('believes a regtest header only when the caller asks for that limit', function () {
      const m = mine(0x207fffff, genesisRootInternal)
      const params = { header: m.header.toBuffer() }
      genesisProof(params).valid.should.equal(false)
      params.powLimit = 0x207fffff
      genesisProof(params).valid.should.equal(true)
      params.powLimit = '207fffff'
      genesisProof(params).valid.should.equal(true, 'compact bits as hex, too')
    })

    it('refuses bits no header may use: negative, zero, or overflowing', function () {
      ;[0x00800000 | 0x01000000, 0x1d000000, 0xff00ffff, 0x23000100].forEach(function (bits) {
        const buf = Buffer.from(GENESIS, 'hex')
        buf.writeUInt32LE(bits >>> 0, 72)
        const r = genesisProof({ header: buf })
        r.powValid.should.equal(false, 'bits 0x' + (bits >>> 0).toString(16))
        r.targetAllowed.should.equal(false, 'bits 0x' + (bits >>> 0).toString(16))
        r.valid.should.equal(false)
      })
    })

    it('enforces minWork above the cap, which is how a difficulty floor is set', function () {
      genesisProof({ minWork: 4e9 }).valid.should.equal(true)
      const r = genesisProof({ minWork: 5e9 })
      r.powValid.should.equal(true)
      r.targetAllowed.should.equal(true)
      r.workSufficient.should.equal(false)
      r.valid.should.equal(false)
      genesisProof({ minWork: '4295032833' }).workSufficient.should.equal(true)
      genesisProof({ minWork: '4295032834' }).workSufficient.should.equal(false)
    })

    it('takes every field from one 80-byte snapshot', function () {
      const asHex = genesisProof()
      const asBuffer = genesisProof({ header: Buffer.from(GENESIS, 'hex') })
      const asHeader = genesisProof({ header: BlockHeader.fromBuffer(Buffer.from(GENESIS, 'hex')) })
      asBuffer.should.deep.equal(asHex)
      asHeader.should.deep.equal(asHex)
      // An instance edited after construction is hashed as its bytes now stand, so it is
      // simply a different block — its stated root cannot outvote its own hash.
      const edited = BlockHeader.fromBuffer(Buffer.from(GENESIS, 'hex'))
      edited.merkleRoot = Buffer.alloc(32, 9)
      const r = genesisProof({ header: edited })
      r.rootMatches.should.equal(false)
      r.blockHash.should.not.equal(GENESIS_ID)
    })

    it('refuses anything that is not 80 bytes of header, and says so', function () {
      const header = BlockHeader.fromBuffer(Buffer.from(GENESIS, 'hex'))
      expect(function () { genesisProof({ header: { merkleRoot: header.merkleRoot } }) })
        .to.throw(/an object stating a merkleRoot is not a header/)
      expect(function () { genesisProof({ header: Buffer.from(GENESIS, 'hex').slice(0, 79) }) })
        .to.throw(/exactly 80 bytes, not 79/)
      expect(function () { genesisProof({ header: null }) }).to.throw(/must be 80 bytes/)
    })

    it('requirePow: false switches off every work check together, as it always did', function () {
      const forged = mine(0x2100ffff, genesisRootInternal)
      const r = genesisProof({ header: forged.header.toBuffer(), requirePow: false, minWork: 5e9 })
      r.valid.should.equal(true)
      // Not checked, so nothing objects: the flags do not report a verdict that was never
      // reached, and the policy inputs are not even read (see the strictness tests below).
      r.targetAllowed.should.equal(true)
      r.workSufficient.should.equal(true)
      r.powValid.should.equal(true, 'it does meet the target it declared')
    })
  })

  // Policy the caller supplies has to be read strictly, or the check it configures
  // quietly stops checking. bn.js parses loosely: 1e21 reads as 23521, '4.3e9' as 4 and
  // 'abc' as 1122 — so a floor set near the chain's real work (about 1e20 per header)
  // would have collapsed to a few thousand, which every header clears.
  describe('the policy inputs are read strictly, never loosely', function () {
    it('refuses a minWork that bn.js would misread, rather than lowering the floor', function () {
      ;[1e21, '4.3e9', 'abc', '0x10', -5, 1.5, {}, true].forEach(function (bad) {
        expect(function () { genesisProof({ minWork: bad }) },
          JSON.stringify(bad)).to.throw(/minWork/)
      })
    })

    it('accepts the forms that cannot be misread, including above 2^53', function () {
      genesisProof({ minWork: 4295032833 }).workSufficient.should.equal(true)
      genesisProof({ minWork: '4295032833' }).workSufficient.should.equal(true)
      genesisProof({ minWork: '100000000000000000000000' }).workSufficient.should.equal(false)
      genesisProof({ minWork: 0 }).workSufficient.should.equal(true)
    })

    it('refuses a powLimit that parseInt would read only part of', function () {
      // parseInt('1d00ffzz', 16) is 0x1d00ff — a different limit, silently.
      ;['1d00ffzz', '1d00ffffZZ', 'zz', '', -1, 1.5, 0x1ffffffff, {}].forEach(function (bad) {
        expect(function () { genesisProof({ powLimit: bad }) },
          JSON.stringify(bad)).to.throw(/powLimit/)
      })
    })

    it('accepts compact bits as a uint32 or hex, with or without 0x', function () {
      ;[0x207fffff, '207fffff', '0x207fffff'].forEach(function (good) {
        genesisProof({ powLimit: good }).targetAllowed.should.equal(true)
      })
    })

    it('does not judge the policy inputs when the work checks are off', function () {
      genesisProof({ requirePow: false, minWork: 'abc', powLimit: 'zz' }).valid.should.equal(true)
    })

    it('refuses header hex with anything after the 160 characters', function () {
      expect(function () { genesisProof({ header: GENESIS + 'zz' }) })
        .to.throw(/exactly 160 hex characters/)
      expect(function () { genesisProof({ header: GENESIS.slice(0, 158) }) })
        .to.throw(/160 hex characters/)
    })
  })

  describe('verifyHeaderChain', function () {
    function regtestChain () {
      const h0 = mine(0x207fffff, genesisRootInternal).header
      const h1 = mine(0x207fffff, Buffer.alloc(32, 1), h0._getHash()).header
      return [h0, h1]
    }

    it('refuses a chain of headers mined at an easy target', function () {
      const r = SPV.verifyHeaderChain(regtestChain())
      r.valid.should.equal(false)
      r.reason.should.match(/easier than the proof-of-work limit at index 0/)
    })

    it('accepts that chain when the caller asks for the regtest limit', function () {
      const chain = regtestChain()
      const r = SPV.verifyHeaderChain(chain, { powLimit: 0x207fffff })
      r.valid.should.equal(true)
      r.count.should.equal(2)
    })

    it('accepts the genesis header under the default limit', function () {
      SPV.verifyHeaderChain([Buffer.from(GENESIS, 'hex')]).valid.should.equal(true)
    })

    it('exposes the limit it applies', function () {
      SPV.POW_LIMIT_BITS.should.equal(0x1d00ffff)
    })
  })
})
