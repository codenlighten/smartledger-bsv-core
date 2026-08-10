'use strict'
/**
 * SmartContract covenant helpers
 * ==============================
 *
 * Shared utilities for building and verifying custom locking scripts &
 * OP_PUSH_TX covenants: a consensus-flag verify() harness, raw BIP-143 preimage
 * access, signing, and fund/spend scaffolding. Used by ./pushtx, ./pels, ./token
 * and ./locks.
 */

import Script = require('../script')
import Interpreter = require('../script/interpreter')
import Opcode = require('../opcode')
import Transaction = require('../transaction')
import Input = require('../transaction/input')
import Output = require('../transaction/output')
import sighash = require('../transaction/sighash')
import BN = require('../crypto/bn')
import Hash = require('../crypto/hash')
import Signature = require('../crypto/signature')
import type { PrivateKey, PayeeLike, VerifyOptions, FundAndSpendOptions, Address } from './types'

// SIGHASH_ALL | SIGHASH_FORKID — the BSV default these covenants are built for.
const SIGHASH = Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID // 0x41

// Post-Genesis consensus + STANDARD RELAY flags — what mainnet miners actually
// enforce. Includes SCRIPT_VERIFY_MINIMALDATA (every push must be minimal) and
// SCRIPT_VERIFY_LOW_S (canonical signatures). Verifying with these flags locally
// mirrors mainnet relay/consensus policy, so a covenant that passes here is
// expected to be accepted on broadcast — catch non-relayable scripts before then.
function flags () {
  const I = Interpreter
  return I.SCRIPT_VERIFY_P2SH |
    I.SCRIPT_VERIFY_STRICTENC |
    I.SCRIPT_VERIFY_DERSIG |
    I.SCRIPT_VERIFY_LOW_S |
    I.SCRIPT_VERIFY_MINIMALDATA |
    I.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
    I.SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
    I.SCRIPT_ENABLE_SIGHASH_FORKID |
    I.SCRIPT_ENABLE_MAGNETIC_OPCODES |
    I.SCRIPT_ENABLE_MONOLITH_OPCODES |
    // REQUIRED, not optional. pushTxCore emits OP_RIGHT/OP_LEFT — see
    // extractHashOutputs and assertSighashType — and those bytes (180/181) are
    // upgradable NOPs on the network until Chronicle activates. Without this
    // flag the interpreter treats them as no-ops, exactly as a pre-Chronicle
    // node does, and the covenant does not verify.
    //
    // The consequence is worth stating plainly: OP_PUSH_TX covenants built by
    // this library DEPEND on Chronicle. They cannot be spent on a pre-Chronicle
    // chain. That was previously invisible because the interpreter ran the
    // string opcodes unconditionally — more permissively than the network.
    I.SCRIPT_ENABLE_CHRONICLE
}

/**
 * Opt into post-Genesis script limits (needed by OP_PUSH_TX covenants).
 * Thin wrapper over Interpreter.useGenesisLimits (added in 4.1.0).
 */
function enableGenesis (max?: number) {
  return Interpreter.useGenesisLimits(max)
}

/**
 * Verify an unlocking script against a locking script through the consensus
 * interpreter. @returns {{ok:boolean, err:string}}
 */
function verify (unlockingScript: Script, lockingScript: Script, opts?: VerifyOptions) {
  opts = opts || {}
  const interp = new Interpreter()
  const ok = interp.verify(
    unlockingScript,
    lockingScript,
    opts.tx || new Transaction(),
    opts.inputIndex || 0,
    opts.flags || flags(),
    new BN(opts.satoshis || 0)
  )
  return { ok, err: interp.errstr || '' }
}

/** Raw BIP-143 preimage (the serialization that is double-SHA256'd), not the digest. */
function rawPreimage (tx: Transaction, inputIndex: number, lockingScript: Script, satoshis: number, sighashType?: number) {
  return sighash.sighashPreimage(
    tx, sighashType || SIGHASH, inputIndex, lockingScript, new BN(satoshis))
}

/** Sighash digest = HASH256(rawPreimage) — useful for asserting OP_PUSH_TX linkage in JS. */
function sighashDigest (tx: Transaction, inputIndex: number, lockingScript: Script, satoshis: number, sighashType?: number) {
  return Hash.sha256sha256(rawPreimage(tx, inputIndex, lockingScript, satoshis, sighashType))
}

/** DER+sighash-byte signature over `lockingScript` for `inputIndex`. */
function signInput (tx: Transaction, privateKey: PrivateKey, inputIndex: number, lockingScript: Script, satoshis: number, sighashType?: number) {
  sighashType = sighashType || SIGHASH
  const sig = sighash.sign(tx, privateKey, sighashType, inputIndex, lockingScript, new BN(satoshis))
  return Buffer.concat([sig.toDER(), Buffer.from([sighashType])])
}

/**
 * Build a funding tx paying `satoshis` into `lockingScript`, plus a spending tx
 * consuming it with the supplied outputs. Returns { funding, spend }; the caller
 * sets spend.inputs[0] script.
 */
function fundAndSpend (lockingScript: Script, satoshis: number, opts?: FundAndSpendOptions) {
  opts = opts || {}
  const funding = new Transaction().addOutput(
    new Output({ script: lockingScript, satoshis }))
  const spend = new Transaction()
  spend.addInput(
    new Input({ prevTxId: funding.hash, outputIndex: 0, script: Script.empty() }),
    lockingScript, satoshis)
  if (opts.outputs) opts.outputs.forEach(function (o: Output) { spend.addOutput(o) })
  return { funding, spend }
}

/** A P2PKH Output object for an address or public key. */
function p2pkhOutput (addressOrPubKey: PayeeLike, satoshis: number) {
  // PublicKey carries toAddress(); an Address and a string do not. The
  // duck-typed probe is what the runtime does, so type it the same way.
  const maybe = addressOrPubKey as { toAddress?: () => unknown }
  const addr = (typeof maybe.toAddress === 'function' ? maybe.toAddress() : addressOrPubKey) as Address
  return new Output({ script: Script.buildPublicKeyHashOut(addr), satoshis })
}

/** Minimal little-endian script-number Buffer (push as data to put a number on-stack). */
function scriptNum (n: number): number | Buffer {
  // Minimal on-stack number: 0..16 and -1 use the dedicated opcodes (OP_0..OP_16,
  // OP_1NEGATE) instead of a data push, so covenant scripts stay MINIMALDATA-clean
  // (mainnet relay policy). Larger values use a minimal scriptNum push. The result
  // is passed to Script.add(), which accepts an opcode number or a Buffer.
  if (n === 0) return Opcode.OP_0
  if (n === -1) return Opcode.OP_1NEGATE
  // Dynamic lookup of OP_1..OP_16; the constants are enumerated on the
  // interface, so index through a string-keyed view rather than widen them.
  if (n >= 1 && n <= 16) return (Opcode as unknown as Record<string, number>)['OP_' + n]!
  return new BN(n).toScriptNumBuffer()
}

export = {
  SIGHASH,
  flags,
  enableGenesis,
  verify,
  rawPreimage,
  sighashDigest,
  signInput,
  fundAndSpend,
  p2pkhOutput,
  scriptNum
}
