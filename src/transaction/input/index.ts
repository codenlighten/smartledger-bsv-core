/**
 * The input family.
 *
 * Mirrors what the JavaScript did — `module.exports = require('./input')`
 * followed by `module.exports.X = require('./x')` — which MUTATES the Input
 * constructor rather than building a new object. `export =` cannot express
 * assign-then-augment directly, so the mutation is written out explicitly and
 * the augmented members are declared on InputConstructor.
 */
import Input = require('./input')
import PublicKeyInput = require('./publickey')
import PublicKeyHashInput = require('./publickeyhash')
import MultiSigInput = require('./multisig')
import MultiSigScriptHashInput = require('./multisigscripthash')

Input.PublicKey = PublicKeyInput
Input.PublicKeyHash = PublicKeyHashInput
Input.MultiSig = MultiSigInput
Input.MultiSigScriptHash = MultiSigScriptHashInput

export = Input
