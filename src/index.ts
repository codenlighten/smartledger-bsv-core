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

/**
 * The namespace is built by assignment, exactly as the JavaScript did, so the
 * shape and the property order are unchanged. What changes is that the
 * requires are hoisted into imports: `export =` cannot coexist with a
 * progressively mutated `module.exports`, and TypeScript moves the export
 * assignment to the end of the emitted file regardless of where it is written.
 */
import _package_json = require('../package.json')
import _crypto_bn = require('./crypto/bn')
import _crypto_ecdsa = require('./crypto/ecdsa')
import _crypto_hash = require('./crypto/hash')
import _crypto_random = require('./crypto/random')
import _crypto_point = require('./crypto/point')
import _crypto_signature = require('./crypto/signature')
import _crypto_shamir = require('./crypto/shamir')
import _crypto_smartledger_verify = require('./crypto/smartledger_verify')
import _encoding_base58 = require('./encoding/base58')
import _encoding_base58check = require('./encoding/base58check')
import _encoding_bufferreader = require('./encoding/bufferreader')
import _encoding_bufferwriter = require('./encoding/bufferwriter')
import _encoding_varint = require('./encoding/varint')
import _util_js = require('./util/js')
import _util_preconditions = require('./util/preconditions')
import _errors = require('./errors')
import _address = require('./address')
import _privatekey = require('./privatekey')
import _publickey = require('./publickey')
import _hdprivatekey = require('./hdprivatekey')
import _hdpublickey = require('./hdpublickey')
import _networks = require('./networks')
import _opcode = require('./opcode')
import _script = require('./script')
import _transaction = require('./transaction')
import _block = require('./block')
import _block_blockheader = require('./block/blockheader')
import _block_merkleblock = require('./block/merkleblock')
import _spv = require('./spv')
import _ecies = require('./ecies')
import _message = require('./message')
import _mnemonic = require('./mnemonic')
import _ordinals = require('./ordinals')
import _covenant = require('./covenant')
import _transaction_sighash = require('./transaction/sighash')
import pkg = require('../package.json')

const bsv: Record<string, any> = {}

bsv.version = _package_json.version

// crypto
bsv.crypto = {}
bsv.crypto.BN = _crypto_bn
bsv.crypto.ECDSA = _crypto_ecdsa
bsv.crypto.Hash = _crypto_hash
bsv.crypto.Random = _crypto_random
bsv.crypto.Point = _crypto_point
bsv.crypto.Signature = _crypto_signature
bsv.crypto.Shamir = _crypto_shamir

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
bsv.crypto.SmartVerify = _crypto_smartledger_verify

// encoding
bsv.encoding = {}
bsv.encoding.Base58 = _encoding_base58
bsv.encoding.Base58Check = _encoding_base58check
bsv.encoding.BufferReader = _encoding_bufferreader
bsv.encoding.BufferWriter = _encoding_bufferwriter
bsv.encoding.Varint = _encoding_varint

// utilities
bsv.util = {}
bsv.util.js = _util_js
bsv.util.preconditions = _util_preconditions

// errors thrown by the library
bsv.errors = _errors

// keys and addresses
bsv.Address = _address
bsv.PrivateKey = _privatekey
bsv.PublicKey = _publickey
bsv.HDPrivateKey = _hdprivatekey
bsv.HDPublicKey = _hdpublickey
bsv.Networks = _networks

// script and transactions
bsv.Opcode = _opcode
bsv.Script = _script
bsv.Transaction = _transaction
bsv.Input = _transaction.Input
bsv.Output = _transaction.Output
bsv.UnspentOutput = _transaction.UnspentOutput
bsv.Signature = _crypto_signature

// blocks and SPV
bsv.Block = _block
bsv.BlockHeader = _block_blockheader
bsv.MerkleBlock = _block_merkleblock
bsv.SPV = _spv

// higher-level primitives
bsv.ECIES = _ecies
bsv.Message = _message
bsv.Mnemonic = _mnemonic
bsv.Shamir = _crypto_shamir

// 1Sat Ordinals (inscriptions, BSV-20, OrdLock)
bsv.Ordinals = _ordinals

// OP_PUSH_TX covenant primitives. Used by Ordinals' OrdLock and by the
// smart-contract package; they depend on nothing above Script/Transaction.
bsv.Covenant = _covenant

// Exposed for advanced use and for the covenant/ordinals machinery.
bsv.Transaction.sighash = _transaction_sighash

export = bsv
