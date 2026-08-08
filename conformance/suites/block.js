'use strict'

const path = require('path')
const fs = require('fs')

// Genesis and block 1 headers — the two most universally published headers in
// Bitcoin, so an independent implementation can check these directly.
const GENESIS_HEADER = '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c'
const BLOCK1_HEADER = '010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299'

const testDataDir = path.join(__dirname, '..', '..', 'test', 'data')
const blockDatPath = path.join(testDataDir, 'blk86756-testnet.dat')
const hasBlockDat = fs.existsSync(blockDatPath)

const cases = {
  'genesis header parse': (bsv) => {
    const h = bsv.BlockHeader.fromBuffer(Buffer.from(GENESIS_HEADER, 'hex'))
    return {
      id: h.id,
      hash: h.hash,
      version: h.version,
      prevHash: h.prevHash,
      merkleRoot: h.merkleRoot,
      time: h.time,
      bits: h.bits,
      nonce: h.nonce,
      roundTrips: h.toBuffer().toString('hex') === GENESIS_HEADER
    }
  },
  'genesis header validates proof of work': (bsv) => {
    const h = bsv.BlockHeader.fromBuffer(Buffer.from(GENESIS_HEADER, 'hex'))
    return { validPoW: h.validProofOfWork(), difficulty: h.getDifficulty(), target: h.getTargetDifficulty().toString(16) }
  },
  'block1 header parse': (bsv) => {
    const h = bsv.BlockHeader.fromBuffer(Buffer.from(BLOCK1_HEADER, 'hex'))
    return { id: h.id, prevHash: h.prevHash, validPoW: h.validProofOfWork() }
  },
  'block1 links to genesis': (bsv) => {
    const g = bsv.BlockHeader.fromBuffer(Buffer.from(GENESIS_HEADER, 'hex'))
    const b1 = bsv.BlockHeader.fromBuffer(Buffer.from(BLOCK1_HEADER, 'hex'))
    return { links: Buffer.from(b1.prevHash).reverse().toString('hex') === g.id }
  },
  'header toObject': (bsv) =>
    bsv.BlockHeader.fromBuffer(Buffer.from(GENESIS_HEADER, 'hex')).toObject(),
  'header rejects truncated buffer': (bsv) =>
    bsv.BlockHeader.fromBuffer(Buffer.from(GENESIS_HEADER.slice(0, 40), 'hex')),
  'header rejects oversized buffer': (bsv) =>
    bsv.BlockHeader.fromBuffer(Buffer.from(GENESIS_HEADER + 'deadbeef', 'hex')),
  // A header with a nonce that does not meet the target must fail PoW.
  'tampered nonce fails proof of work': (bsv) => {
    const buf = Buffer.from(GENESIS_HEADER, 'hex')
    buf[buf.length - 1] ^= 0xff
    return bsv.BlockHeader.fromBuffer(buf).validProofOfWork()
  }
}

if (hasBlockDat) {
  const blockBuf = fs.readFileSync(blockDatPath)
  cases['real block parse'] = (bsv) => {
    const b = bsv.Block.fromRawBlock(blockBuf)
    return {
      id: b.id,
      txCount: b.transactions.length,
      merkleRoot: b.getMerkleRoot().toString('hex'),
      validMerkleRoot: b.validMerkleRoot()
    }
  }
  cases['real block merkle tree'] = (bsv) => {
    const b = bsv.Block.fromRawBlock(blockBuf)
    return { tree: b.getMerkleTree().slice(0, 8).map((n) => Buffer.from(n).toString('hex')) }
  }
  cases['real block round-trips'] = (bsv) => {
    const b = bsv.Block.fromRawBlock(blockBuf)
    return b.toBuffer().length
  }
}

module.exports = { name: 'block', cases }
