'use strict'

// Helpers for Bitcoin Core's data-driven test formats.
//
// These live in the corpus rather than in a test file because the corpus must
// keep running against a reimplementation. In the current repo the equivalent
// of fromBitcoindString() is monkey-patched onto Script inside
// test/script/interpreter.js, which means it disappears the moment those tests
// are rewritten — exactly when we most need the vectors to keep working.

/**
 * Parse Bitcoin Core's script string format.
 *
 * Token grammar:
 *   0x<hex>   raw bytes, spliced in verbatim (used to build malformed scripts)
 *   '<text>'  a data push of the literal text
 *   OP_NAME   an opcode, with or without the OP_ prefix
 *   <number>  a minimally-encoded script number push
 */
function scriptFromBitcoindString (bsv, str) {
  const { Script, Opcode, BufferWriter, BN } = {
    Script: bsv.Script,
    Opcode: bsv.Opcode,
    BufferWriter: bsv.encoding.BufferWriter,
    BN: bsv.crypto.BN
  }

  const bw = new BufferWriter()
  for (const token of String(str).split(' ')) {
    if (token === '') continue

    if (token[0] === '0' && token[1] === 'x') {
      bw.write(Buffer.from(token.slice(2), 'hex'))
    } else if (token[0] === "'") {
      bw.write(new Script().add(Buffer.from(token.slice(1, token.length - 1))).toBuffer())
    } else if (typeof Opcode['OP_' + token] !== 'undefined') {
      bw.writeUInt8(Opcode['OP_' + token])
    } else if (typeof Opcode[token] === 'number') {
      bw.writeUInt8(Opcode[token])
    } else if (!isNaN(parseInt(token, 10))) {
      bw.write(new Script().add(new BN(token).toScriptNumBuffer()).toBuffer())
    } else {
      throw new Error('Could not determine type of script value: ' + token)
    }
  }
  return Script.fromBuffer(bw.concat())
}

/**
 * Build the credit/spend transaction pair that Bitcoin Core's script tests
 * evaluate against, and run the interpreter over it.
 *
 * Returns `{ verified, errstr }`.
 */
function runScriptTest (bsv, scriptSig, scriptPubkey, flags, inputAmount) {
  const { Transaction, Script } = bsv
  const amount = inputAmount || 0

  const credtx = new Transaction()
  credtx.uncheckedAddInput(new Transaction.Input({
    prevTxId: '0'.repeat(64),
    outputIndex: 0xffffffff,
    sequenceNumber: 0xffffffff,
    script: new Script('OP_0 OP_0')
  }))
  credtx.addOutput(new Transaction.Output({ script: scriptPubkey, satoshis: amount }))

  const spendtx = new Transaction()
  spendtx.uncheckedAddInput(new Transaction.Input({
    prevTxId: credtx.id,
    outputIndex: 0,
    sequenceNumber: 0xffffffff,
    script: scriptSig
  }))
  spendtx.addOutput(new Transaction.Output({ script: new Script(), satoshis: amount }))

  const interp = new bsv.Script.Interpreter()
  const verified = interp.verify(
    scriptSig, scriptPubkey, spendtx, 0, flags, new (bsv.crypto.BN)(amount)
  )
  return { verified, errstr: interp.errstr }
}

/**
 * Translate a Core flag string ("P2SH,STRICTENC") into a flags bitmask.
 *
 * Flags live under two prefixes: SCRIPT_VERIFY_ for the standardness/policy
 * checks and SCRIPT_ENABLE_ for the BSV opcode-restoration switches
 * (MAGNETIC_OPCODES, SIGHASH_FORKID, REPLAY_PROTECTION). Trying only the first
 * prefix silently drops the second set, which makes 65 LSHIFT/RSHIFT vectors
 * look like consensus failures when they are really unparsed flags.
 *
 * Unknown names therefore throw rather than being skipped: a silently ignored
 * flag turns a passing corpus into a lie.
 */
function flagsFromString (bsv, flagstr) {
  const Interpreter = bsv.Script.Interpreter
  let flags = 0
  for (const raw of String(flagstr).split(',')) {
    const name = raw.trim()
    if (!name) continue
    const verify = 'SCRIPT_VERIFY_' + name
    const enable = 'SCRIPT_ENABLE_' + name
    if (Interpreter[verify] !== undefined) flags |= Interpreter[verify]
    else if (Interpreter[enable] !== undefined) flags |= Interpreter[enable]
    else throw new Error('unknown script flag: ' + name)
  }
  return flags
}

module.exports = { scriptFromBitcoindString, runScriptTest, flagsFromString }
