'use strict'

/**
 * @smartledger/bsv-core — Bitcoin SV primitives.
 *
 * Keys, addresses, script, transactions, encoding, block headers, SPV, ECIES,
 * message signing, BIP39 mnemonics, 1Sat Ordinals, and OP_PUSH_TX covenants.
 *
 * Application protocols (Legal Token Protocol, the attestation framework, the
 * smart-contract authoring tooling) live in sibling packages that depend on
 * this one. They are not re-exported here.
 *
 * Differences from @smartledger/bsv worth knowing about:
 *
 *   - No `bsv.deps`. Modules import their dependencies directly; nothing reads
 *     a shared namespace off the package root, so load order is not
 *     load-bearing and there are no require cycles.
 *   - No `global._bsv` version guard. It reported duplicate instances by
 *     mutating a global, which is itself a side effect at import time.
 *   - No `Mnemonic.bsv` back-reference to the whole library.
 *   - No `isHardened` / `hardenedBy` / `securityFeatures` advertisement. The
 *     previous values described protections that were not wired into the
 *     default verify path; rather than restate them, this package will make
 *     the verify path itself strict.
 */

const bsv = module.exports

bsv.version = require('../package.json').version

// crypto
bsv.crypto = {}
bsv.crypto.BN = require('./crypto/bn')
bsv.crypto.ECDSA = require('./crypto/ecdsa')
bsv.crypto.Hash = require('./crypto/hash')
bsv.crypto.Random = require('./crypto/random')
bsv.crypto.Point = require('./crypto/point')
bsv.crypto.Signature = require('./crypto/signature')
bsv.crypto.Shamir = require('./crypto/shamir')

// Strict signature verification: enforces low-S, rejects zero/out-of-range
// components, and validates the message-hash length — checks the default
// ECDSA.verify path does not currently make.
//
// It is OPT-IN, which is the problem: nothing in lib/ calls it, so the
// hardening it provides applies only to callers who know to ask for it. The
// previous package advertised these protections via `isHardened` and
// `securityFeatures` on the root namespace while the default verify path
// bypassed them entirely; that advertisement is deliberately not carried here.
//
// Folding these checks INTO the default verify path (or deleting this module)
// is an API-design decision, tracked for the next phase. Carried meanwhile so
// its security assertions keep running rather than being silently dropped.
bsv.crypto.SmartVerify = require('./crypto/smartledger_verify')

// encoding
bsv.encoding = {}
bsv.encoding.Base58 = require('./encoding/base58')
bsv.encoding.Base58Check = require('./encoding/base58check')
bsv.encoding.BufferReader = require('./encoding/bufferreader')
bsv.encoding.BufferWriter = require('./encoding/bufferwriter')
bsv.encoding.Varint = require('./encoding/varint')

// utilities
bsv.util = {}
bsv.util.js = require('./util/js')
bsv.util.preconditions = require('./util/preconditions')

// errors thrown by the library
bsv.errors = require('./errors')

// keys and addresses
bsv.Address = require('./address')
bsv.PrivateKey = require('./privatekey')
bsv.PublicKey = require('./publickey')
bsv.HDPrivateKey = require('./hdprivatekey')
bsv.HDPublicKey = require('./hdpublickey')
bsv.Networks = require('./networks')

// script and transactions
bsv.Opcode = require('./opcode')
bsv.Script = require('./script')
bsv.Transaction = require('./transaction')
bsv.Input = require('./transaction').Input
bsv.Output = require('./transaction').Output
bsv.UnspentOutput = require('./transaction').UnspentOutput
bsv.Signature = require('./crypto/signature')

// blocks and SPV
bsv.Block = require('./block')
bsv.BlockHeader = require('./block/blockheader')
bsv.MerkleBlock = require('./block/merkleblock')
bsv.SPV = require('./spv')

// higher-level primitives
bsv.ECIES = require('./ecies')
bsv.Message = require('./message')
bsv.Mnemonic = require('./mnemonic')
bsv.Shamir = require('./crypto/shamir')

// 1Sat Ordinals (inscriptions, BSV-20, OrdLock)
bsv.Ordinals = require('./ordinals')

// OP_PUSH_TX covenant primitives. Used by Ordinals' OrdLock and by the
// smart-contract package; they depend on nothing above Script/Transaction.
bsv.Covenant = require('./covenant')

// Exposed for advanced use and for the covenant/ordinals machinery.
bsv.Transaction.sighash = require('./transaction/sighash')
