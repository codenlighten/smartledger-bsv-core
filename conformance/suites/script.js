'use strict'

const { SCRIPTS, KEYS, ADDRESSES, BUFFERS } = require('../vectors')

const hex = (s) => Buffer.from(s, 'hex')
const cases = {}

// --- Parsing and re-serialization ------------------------------------------
for (const [name, h] of Object.entries(SCRIPTS)) {
  if (typeof h !== 'string') continue
  cases[`parse ${name}`] = (bsv) => {
    const s = bsv.Script.fromHex(h)
    return {
      hex: s.toHex(),
      asm: s.toASM(),
      str: s.toString(),
      chunks: s.chunks.length,
      roundTrips: s.toHex() === h
    }
  }
}

for (const asm of SCRIPTS.asm) {
  cases[`fromASM "${asm}"`] = (bsv) => {
    const s = bsv.Script.fromASM(asm)
    return { hex: s.toHex(), asm: s.toASM(), roundTrips: s.toASM() === asm }
  }
}

Object.assign(cases, {
  // --- Classification -----------------------------------------------------
  'classify p2pkh': (bsv) => {
    const s = bsv.Script.fromHex(SCRIPTS.p2pkh)
    return {
      isPublicKeyHashOut: s.isPublicKeyHashOut(),
      isScriptHashOut: s.isScriptHashOut(),
      isPublicKeyOut: s.isPublicKeyOut(),
      isDataOut: s.isDataOut(),
      type: s.classify()
    }
  },
  'classify p2sh': (bsv) => bsv.Script.fromHex(SCRIPTS.p2sh).classify(),
  'classify p2pk': (bsv) => bsv.Script.fromHex(SCRIPTS.p2pk).classify(),
  'classify opreturn': (bsv) => {
    const s = bsv.Script.fromHex(SCRIPTS.opReturn)
    return { type: s.classify(), isDataOut: s.isDataOut(), data: s.getData() }
  },
  'classify multisig': (bsv) => bsv.Script.fromHex(SCRIPTS.multisig).classify(),
  'classify empty': (bsv) => bsv.Script.fromHex('').classify(),

  // --- Builders -----------------------------------------------------------
  'build p2pkh from address': (bsv) =>
    bsv.Script.buildPublicKeyHashOut(bsv.Address.fromString(ADDRESSES.mainnetP2PKH)).toHex(),
  'build p2pk from pubkey': (bsv) =>
    bsv.Script.buildPublicKeyOut(bsv.PrivateKey.fromWIF(KEYS.oneWIFCompressed).publicKey).toHex(),
  'build scripthash out': (bsv) =>
    bsv.Script.buildScriptHashOut(bsv.Script.fromHex(SCRIPTS.multisig)).toHex(),
  'build data out short': (bsv) => bsv.Script.buildDataOut(hex(BUFFERS.hello)).toHex(),
  'build safe data out': (bsv) => bsv.Script.buildSafeDataOut(hex(BUFFERS.hello)).toHex(),
  'build data out empty': (bsv) => bsv.Script.buildDataOut(hex('')).toHex(),
  'build multisig 2-of-2': (bsv) => {
    const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed).publicKey
    const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2).publicKey
    return bsv.Script.buildMultisigOut([a, b], 2).toHex()
  },
  'build multisig sorts keys by default': (bsv) => {
    const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed).publicKey
    const b = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed2).publicKey
    return {
      ab: bsv.Script.buildMultisigOut([a, b], 2).toHex(),
      ba: bsv.Script.buildMultisigOut([b, a], 2).toHex(),
      unsortedAb: bsv.Script.buildMultisigOut([a, b], 2, { noSorting: true }).toHex(),
      unsortedBa: bsv.Script.buildMultisigOut([b, a], 2, { noSorting: true }).toHex()
    }
  },
  'build multisig threshold above key count': (bsv) => {
    const a = bsv.PrivateKey.fromWIF(KEYS.mainnetCompressed).publicKey
    return bsv.Script.buildMultisigOut([a], 2).toHex()
  },

  // --- Push-opcode boundaries ---------------------------------------------
  // 75/76 selects OP_PUSHDATA1, 255/256 selects OP_PUSHDATA2, and 65535/65536
  // selects OP_PUSHDATA4. Each boundary is an off-by-one waiting to happen.
  'push size boundaries': (bsv) => {
    const sizes = [0, 1, 75, 76, 77, 254, 255, 256, 65535, 65536]
    return sizes.map((n) => {
      const s = new bsv.Script().add(Buffer.alloc(n, 0xab))
      return { size: n, prefix: s.toBuffer().slice(0, 6).toString('hex'), total: s.toBuffer().length }
    })
  },
  'add 520-byte element': (bsv) => new bsv.Script().add(hex(BUFFERS.long520)).toBuffer().length,
  'add 521-byte element': (bsv) => new bsv.Script().add(hex(BUFFERS.long521)).toBuffer().length,

  // --- Malformed input ----------------------------------------------------
  // A truncated push must not silently produce a shorter script.
  'truncated pushdata1': (bsv) => bsv.Script.fromHex('4c05' + '0102').toASM(),
  'truncated pushdata2': (bsv) => bsv.Script.fromHex('4d0500' + '0102').toASM(),
  'truncated direct push': (bsv) => bsv.Script.fromHex('05' + '0102').toASM(),
  'push claiming more than available': (bsv) => bsv.Script.fromHex('ff').toASM(),
  'odd-length hex rejected': (bsv) => bsv.Script.fromHex('abc'),
  'fromASM with invalid opcode': (bsv) => bsv.Script.fromASM('OP_NOTAREALOPCODE'),
  'fromASM with odd hex': (bsv) => bsv.Script.fromASM('abc'),

  // --- Misc ---------------------------------------------------------------
  'empty script properties': (bsv) => {
    const s = bsv.Script.empty()
    return { hex: s.toHex(), asm: s.toASM(), chunks: s.chunks.length, classify: s.classify() }
  },
  'script from address p2pkh': (bsv) =>
    bsv.Script.fromAddress(ADDRESSES.mainnetP2PKH).toHex(),
  'script from address p2sh': (bsv) =>
    bsv.Script.fromAddress(ADDRESSES.mainnetP2SH).toHex(),
  'script toAddress from p2pkh out': (bsv) =>
    bsv.Script.fromHex(SCRIPTS.p2pkh).toAddress('livenet').toString(),
  'script getData on p2pkh (not data)': (bsv) => bsv.Script.fromHex(SCRIPTS.p2pkh).getData()
})

module.exports = { name: 'script', cases }
