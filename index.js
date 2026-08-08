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

bsv.version = require('./package.json').version

// crypto
bsv.crypto = {}
bsv.crypto.BN = require('./lib/crypto/bn')
bsv.crypto.ECDSA = require('./lib/crypto/ecdsa')
bsv.crypto.Hash = require('./lib/crypto/hash')
bsv.crypto.Random = require('./lib/crypto/random')
bsv.crypto.Point = require('./lib/crypto/point')
bsv.crypto.Signature = require('./lib/crypto/signature')
bsv.crypto.Shamir = require('./lib/crypto/shamir')

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
bsv.crypto.SmartVerify = require('./lib/crypto/smartledger_verify')

// encoding
bsv.encoding = {}
bsv.encoding.Base58 = require('./lib/encoding/base58')
bsv.encoding.Base58Check = require('./lib/encoding/base58check')
bsv.encoding.BufferReader = require('./lib/encoding/bufferreader')
bsv.encoding.BufferWriter = require('./lib/encoding/bufferwriter')
bsv.encoding.Varint = require('./lib/encoding/varint')

// utilities
bsv.util = {}
bsv.util.js = require('./lib/util/js')
bsv.util.preconditions = require('./lib/util/preconditions')

// errors thrown by the library
bsv.errors = require('./lib/errors')

// keys and addresses
bsv.Address = require('./lib/address')
bsv.PrivateKey = require('./lib/privatekey')
bsv.PublicKey = require('./lib/publickey')
bsv.HDPrivateKey = require('./lib/hdprivatekey')
bsv.HDPublicKey = require('./lib/hdpublickey')
bsv.Networks = require('./lib/networks')

// script and transactions
bsv.Opcode = require('./lib/opcode')
bsv.Script = require('./lib/script')
bsv.Transaction = require('./lib/transaction')
bsv.Input = require('./lib/transaction').Input
bsv.Output = require('./lib/transaction').Output
bsv.UnspentOutput = require('./lib/transaction').UnspentOutput
bsv.Signature = require('./lib/crypto/signature')

// blocks and SPV
bsv.Block = require('./lib/block')
bsv.BlockHeader = require('./lib/block/blockheader')
bsv.MerkleBlock = require('./lib/block/merkleblock')
bsv.SPV = require('./lib/spv')

// higher-level primitives
bsv.ECIES = require('./lib/ecies')
bsv.Message = require('./lib/message')
bsv.Mnemonic = require('./lib/mnemonic')
bsv.Shamir = require('./lib/crypto/shamir')

// 1Sat Ordinals (inscriptions, BSV-20, OrdLock)
bsv.Ordinals = require('./lib/ordinals')

// OP_PUSH_TX covenant primitives. Used by Ordinals' OrdLock and by the
// smart-contract package; they depend on nothing above Script/Transaction.
bsv.Covenant = require('./lib/covenant')

// Exposed for advanced use and for the covenant/ordinals machinery.
bsv.Transaction.sighash = require('./lib/transaction/sighash')
