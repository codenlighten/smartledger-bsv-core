'use strict'

/* global describe, it */

// BSV-20 / BSV-21 fungible-token inscriptions: build/parse round-trips + validation.

require('chai').should()
const bsv = require('../..')
const B = bsv.Ordinals.BSV20
const Ord = bsv.Ordinals

describe('Ordinals BSV-20 fungible tokens', function () {
  const key = bsv.PrivateKey.fromRandom()
  const address = key.toAddress()

  it('deploys a v1 ticker token and round-trips through parse', function () {
    const s = B.buildDeploy({ address, tick: 'ORDI', max: '21000000', lim: '1000', dec: 18 })
    const p = B.parseBsv20(s)
    p.p.should.equal('bsv-20')
    p.op.should.equal('deploy')
    p.tick.should.equal('ORDI')
    p.max.should.equal('21000000')
    p.lim.should.equal('1000')
    p.dec.should.equal('18')
    // The payload rides in an inscription with the bsv-20 content-type.
    Ord.parseInscription(s).contentType.should.equal('application/bsv-20')
    // The base lock is the owner's P2PKH.
    Ord.parseInscription(s).lock.toHex().should.equal(bsv.Script.buildPublicKeyHashOut(address).toHex())
  })

  it('mints and transfers a v1 ticker token', function () {
    const mint = B.parseBsv20(B.buildMint({ address, tick: 'ORDI', amt: '1000' }))
    mint.op.should.equal('mint')
    mint.tick.should.equal('ORDI')
    mint.amt.should.equal('1000')

    const xfer = B.parseBsv20(B.buildTransfer({ address, tick: 'ORDI', amt: '250' }))
    xfer.op.should.equal('transfer')
    xfer.tick.should.equal('ORDI')
    xfer.amt.should.equal('250')
  })

  it('deploy+mints a BSV-21 (id-based) token and transfers by id', function () {
    const dm = B.parseBsv20(B.buildDeployMint({ address, amt: '1000000', dec: 8, sym: 'XYZ' }))
    dm.op.should.equal('deploy+mint')
    dm.amt.should.equal('1000000')
    dm.dec.should.equal('8')
    dm.sym.should.equal('XYZ')

    const id = 'a'.repeat(64) + '_0'
    const xfer = B.parseBsv20(B.buildTransfer({ address, id, amt: '5' }))
    xfer.op.should.equal('transfer')
    xfer.id.should.equal(id)
    xfer.amt.should.equal('5')
    ;(xfer.tick === undefined).should.equal(true)
  })

  it('preserves integer amounts larger than 2^53 exactly (string, never a JS number)', function () {
    // uint64 max: far beyond 2^53, and the largest amount the spec allows. The value this
    // used to test (26 digits) exceeded uint64 and would have been burned by an indexer.
    const huge = '18446744073709551615'
    const p = B.parseBsv20(B.buildMint({ address, tick: 'BIG', amt: huge }))
    p.amt.should.equal(huge)
  })

  it('accepts numeric amounts and normalizes them to strings', function () {
    const p = B.parseBsv20(B.buildMint({ address, tick: 'NUM', amt: 42 }))
    p.amt.should.equal('42')
  })

  // Code-review finding #4: leading-zero integer strings are canonicalized (indexers expect
  // canonical decimals), while preserving arbitrary precision.
  it('canonicalizes leading-zero amount strings', function () {
    B.parseBsv20(B.buildMint({ address, tick: 'ORDI', amt: '007' })).amt.should.equal('7')
    B.parseBsv20(B.buildDeploy({ address, tick: 'ORDI', max: '000100' })).max.should.equal('100')
    // canonicalization does not corrupt a huge value
    const huge = '18446744073709551615'
    B.parseBsv20(B.buildMint({ address, tick: 'ORDI', amt: '0' + huge })).amt.should.equal(huge)
  })

  it('builds a 1-sat token output', function () {
    const out = B.createMintOutput({ address, tick: 'ORDI', amt: '1' })
    out.satoshis.should.equal(1)
    B.isBsv20(out.script).should.equal(true)
  })

  it('round-trips through hex serialization', function () {
    const s = B.buildDeploy({ address, tick: 'HEX', max: '1000' })
    const p = B.parseBsv20(s.toHex())
    p.tick.should.equal('HEX')
    p.max.should.equal('1000')
  })

  it('parses a raw JSON string or an already-parsed object', function () {
    const json = '{"p":"bsv-20","op":"mint","tick":"ORDI","amt":"1"}'
    B.parseBsv20(json).amt.should.equal('1')
    B.parseBsv20({ p: 'bsv-20', op: 'mint', tick: 'ORDI', amt: '1' }).op.should.equal('mint')
  })

  it('isBsv20 is false for a plain inscription and a P2PKH script', function () {
    const plain = Ord.buildInscription({ address, contentType: 'text/plain', content: 'hi' })
    B.isBsv20(plain).should.equal(false)
    B.isBsv20(bsv.Script.buildPublicKeyHashOut(address)).should.equal(false)
    ;(B.parseBsv20(plain) === null).should.equal(true)
  })

  describe('validation', function () {
    it('rejects a tick longer than 4 UTF-8 bytes', function () {
      ;(function () { B.buildDeploy({ address, tick: 'TOOLONG', max: '1' }) }).should.throw(/1–4 UTF-8 bytes/)
    })
    it('rejects a non-integer / negative amount', function () {
      ;(function () { B.buildMint({ address, tick: 'ORDI', amt: '1.5' }) }).should.throw(/non-negative integer/)
      ;(function () { B.buildMint({ address, tick: 'ORDI', amt: -5 }) }).should.throw(/non-negative integer/)
    })
    it('rejects a zero amount for mint/transfer', function () {
      ;(function () { B.buildMint({ address, tick: 'ORDI', amt: '0' }) }).should.throw(/greater than zero/)
    })
    it('rejects dec out of the 0…18 range', function () {
      ;(function () { B.buildDeploy({ address, tick: 'ORDI', max: '1', dec: 19 }) }).should.throw(/dec must be/)
    })
    it('rejects a malformed BSV-21 id', function () {
      ;(function () { B.buildTransfer({ address, id: 'notanid', amt: '1' }) }).should.throw(/txid.*vout|<txid>/)
    })
    it('requires an owner (address or lock)', function () {
      ;(function () { B.buildMint({ tick: 'ORDI', amt: '1' }) }).should.throw(/address or a lock/)
    })
  })

  // Checked against the BSV-20 / BSV-21 specification at docs.1satordinals.com.
  describe('specification conformance', function () {
    const OUTPOINT = '3b31'.repeat(16) + '_0'
    const UINT64_MAX = '18446744073709551615'

    it('accepts lim: 0, which the spec defines as unlimited', function () {
      // "lim | No | String | Per-mint limit; 0 or omitted = unlimited"
      B.parseBsv20(B.buildDeploy({ address, tick: 'ORDI', max: '21000000', lim: 0 }))
        .lim.should.equal('0')
      B.parseBsv20(B.buildDeploy({ address, tick: 'ORDI', max: '21000000', lim: '0' }))
        .lim.should.equal('0')
    })

    it('accepts an amount of exactly uint64 max but rejects one above it', function () {
      // "Amounts in BSV-21: strings representing uint64" — larger values are emitted
      // happily as JSON and then discarded by indexers, burning the tokens.
      B.parseBsv20(B.buildDeploy({ address, tick: 'ORDI', max: UINT64_MAX }))
        .max.should.equal(UINT64_MAX)
      ;(function () {
        B.buildDeploy({ address, tick: 'ORDI', max: '18446744073709551616' })
      }).should.throw(/exceeds the uint64 maximum/)
      ;(function () {
        B.buildMint({ address, tick: 'ORDI', amt: '9'.repeat(26) })
      }).should.throw(/exceeds the uint64 maximum/)
    })

    it('rejects a numeric amount past 2^53, which is already imprecise', function () {
      (function () {
        B.buildMint({ address, tick: 'ORDI', amt: 1e17 })
      }).should.throw(/MAX_SAFE_INTEGER/)
    })

    it('rejects non-string sym / icon instead of stringifying them', function () {
      (function () {
        B.buildDeployMint({ address, amt: '100', sym: {} })
      }).should.throw(/sym must be a string, got an object/)
      ;(function () {
        B.buildDeployMint({ address, amt: '100', icon: 42 })
      }).should.throw(/icon must be a string/)
    })

    it('requires icon to be an outpoint reference, as the spec defines it', function () {
      (function () {
        B.buildDeployMint({ address, amt: '100', icon: 'https://example.com/i.png' })
      }).should.throw(/outpoint reference/)
      B.parseBsv20(B.buildDeployMint({ address, amt: '100', icon: OUTPOINT }))
        .icon.should.equal(OUTPOINT)
    })

    // parseBsv20/isBsv20 are documented to report VALIDITY. They previously returned any
    // JSON object carrying p:'bsv-20' and a string op, including payloads no indexer acts on.
    describe('parseBsv20 enforces the validity it reports', function () {
      function rejects (label, payload) {
        it('rejects ' + label, function () {
          const json = JSON.stringify(payload)
          B.isBsv20(json).should.equal(false)
          ;(B.parseBsv20(json) === null).should.equal(true)
        })
      }
      rejects('a transfer with no amount and no token', { p: 'bsv-20', op: 'transfer' })
      rejects('a mint with no amount', { p: 'bsv-20', op: 'mint', tick: 'ORDI' })
      rejects('a deploy with no max', { p: 'bsv-20', op: 'deploy', tick: 'ORDI' })
      rejects('an operation the spec does not define', { p: 'bsv-20', op: 'not-an-op' })
      rejects('a transfer naming both tick and id', { p: 'bsv-20', op: 'transfer', tick: 'A', id: OUTPOINT, amt: '1' })
      rejects('an auth carrying amt, which the spec forbids', { p: 'bsv-20', op: 'auth', id: OUTPOINT, amt: '1' })
      rejects('a deploy+auth carrying amt, which the spec forbids', { p: 'bsv-20', op: 'deploy+auth', amt: '1' })
      rejects('a ticker longer than 4 bytes', { p: 'bsv-20', op: 'mint', tick: 'TOOLONG', amt: '1' })
      rejects('a malformed token id', { p: 'bsv-20', op: 'transfer', id: 'nope', amt: '1' })
      rejects('an amount above uint64', { p: 'bsv-20', op: 'mint', tick: 'A', amt: '9'.repeat(26) })
      rejects('dec out of range', { p: 'bsv-20', op: 'deploy', tick: 'A', max: '1', dec: '19' })

      it('accepts the spec operations this library does not yet emit', function () {
        // Reading the chain is not the same as writing it: burn/auth/deploy+auth are valid
        // BSV-21 and must be recognised even though there is no builder for them yet.
        B.isBsv20(JSON.stringify({ p: 'bsv-20', op: 'burn', id: OUTPOINT, amt: '5' })).should.equal(true)
        B.isBsv20(JSON.stringify({ p: 'bsv-20', op: 'auth', id: OUTPOINT })).should.equal(true)
        B.isBsv20(JSON.stringify({ p: 'bsv-20', op: 'deploy+auth', sym: 'STABLE' })).should.equal(true)
      })

      it('tolerates a non-canonical on-chain amount when reading', function () {
        // Our builder emits canonical amounts, but other people's payloads are not ours
        // to reject over leading zeros.
        B.isBsv20(JSON.stringify({ p: 'bsv-20', op: 'mint', tick: 'A', amt: '007' })).should.equal(true)
      })

      it('still round-trips everything this library builds', function () {
        B.isBsv20(B.buildDeploy({ address, tick: 'ORDI', max: '21000000' })).should.equal(true)
        B.isBsv20(B.buildMint({ address, tick: 'ORDI', amt: '1' })).should.equal(true)
        B.isBsv20(B.buildTransfer({ address, id: OUTPOINT, amt: '1' })).should.equal(true)
        B.isBsv20(B.buildDeployMint({ address, amt: '1000' })).should.equal(true)
        B.isBsv20(B.buildBurn({ address, id: OUTPOINT, amt: '1' })).should.equal(true)
        B.isBsv20(B.buildAuth({ address, id: OUTPOINT })).should.equal(true)
        B.isBsv20(B.buildDeployAuth({ address, sym: 'STABLE' })).should.equal(true)
      })
    })
  })

  // BSV-21 authority model: deploy+auth creates no supply, an auth output carries the right
  // to mint, and mint names its token by `id`. Previously only the fixed-supply deploy+mint
  // path could be built, so these operations could be read but never written.
  describe('BSV-21 authority operations', function () {
    const OUTPOINT = '3b31'.repeat(16) + '_0'

    it('mints by id, which requires an auth input on chain', function () {
      const p = B.parseBsv20(B.buildMint({ address, id: OUTPOINT, amt: '1000000' }))
      p.op.should.equal('mint')
      p.id.should.equal(OUTPOINT)
      p.amt.should.equal('1000000')
      ;(p.tick === undefined).should.equal(true)
    })

    it('leaves the v1 ticker mint byte-for-byte unchanged', function () {
      const p = B.parseBsv20(B.buildMint({ address, tick: 'ORDI', amt: '1000' }))
      JSON.stringify(p).should.equal('{"p":"bsv-20","op":"mint","tick":"ORDI","amt":"1000"}')
    })

    it('refuses to guess which token an operation means', function () {
      // Naming both used to silently drop the tick — a different token, not a preference.
      (function () {
        B.buildMint({ address, tick: 'ORDI', id: OUTPOINT, amt: '1' })
      }).should.throw(/not both/)
      ;(function () {
        B.buildTransfer({ address, tick: 'ORDI', id: OUTPOINT, amt: '1' })
      }).should.throw(/not both/)
      ;(function () {
        B.buildMint({ address, amt: '1' })
      }).should.throw(/requires `tick` \(v1\) or `id`/)
    })

    it('builds a burn', function () {
      const p = B.parseBsv20(B.buildBurn({ address, id: OUTPOINT, amt: '5' }))
      p.op.should.equal('burn')
      p.id.should.equal(OUTPOINT)
      p.amt.should.equal('5')
    })

    it('rejects a ticker burn, which the spec does not define', function () {
      (function () {
        B.buildBurn({ address, tick: 'ORDI', amt: '5' })
      }).should.throw(/BSV-21 operation/)
    })

    it('builds deploy+auth with no supply', function () {
      const p = B.parseBsv20(B.buildDeployAuth({ address, sym: 'STABLE', dec: 6 }))
      p.op.should.equal('deploy+auth')
      p.sym.should.equal('STABLE')
      p.dec.should.equal('6')
      ;(p.amt === undefined).should.equal(true)
      // Every field is optional.
      B.parseBsv20(B.buildDeployAuth({ address })).op.should.equal('deploy+auth')
    })

    it('builds an auth output carrying no amount', function () {
      const p = B.parseBsv20(B.buildAuth({ address, id: OUTPOINT }))
      p.op.should.equal('auth')
      p.id.should.equal(OUTPOINT)
      ;(p.amt === undefined).should.equal(true)
    })

    it('refuses to attach an amt where the spec forbids one', function () {
      (function () {
        B.buildAuth({ address, id: OUTPOINT, amt: '1' })
      }).should.throw(/must not carry an amt/)
      ;(function () {
        B.buildDeployAuth({ address, sym: 'X', amt: '1' })
      }).should.throw(/must not carry an amt/)
    })

    it('applies the same amount rules as the other operations', function () {
      (function () {
        B.buildBurn({ address, id: OUTPOINT, amt: '0' })
      }).should.throw(/greater than zero/)
      ;(function () {
        B.buildBurn({ address, id: OUTPOINT, amt: '9'.repeat(26) })
      }).should.throw(/exceeds the uint64 maximum/)
      ;(function () {
        B.buildMint({ address, id: 'notanid', amt: '1' })
      }).should.throw(/<txid>/)
      ;(function () {
        B.buildDeployAuth({ address, sym: {} })
      }).should.throw(/sym must be a string/)
    })

    it('builds 1-sat outputs for each new operation', function () {
      const outs = [
        B.createBurnOutput({ address, id: OUTPOINT, amt: '5' }),
        B.createAuthOutput({ address, id: OUTPOINT }),
        B.createDeployAuthOutput({ address, sym: 'STABLE' })
      ]
      outs.forEach(function (o) {
        o.satoshis.should.equal(1)
        B.isBsv20(o.script).should.equal(true)
      })
    })

    it('round-trips a full authority lifecycle', function () {
      // deploy+auth -> auth output delegating mint rights -> mint by id -> burn.
      const deploy = B.parseBsv20(B.buildDeployAuth({ address, sym: 'GOLD', dec: 8 }))
      const auth = B.parseBsv20(B.buildAuth({ address, id: OUTPOINT }))
      const mint = B.parseBsv20(B.buildMint({ address, id: OUTPOINT, amt: '1000' }))
      const burn = B.parseBsv20(B.buildBurn({ address, id: OUTPOINT, amt: '400' }))
      deploy.op.should.equal('deploy+auth')
      auth.op.should.equal('auth')
      mint.amt.should.equal('1000')
      burn.amt.should.equal('400')
      ;[deploy, auth, mint, burn].forEach(function (p) { p.p.should.equal('bsv-20') })
    })
  })
})
