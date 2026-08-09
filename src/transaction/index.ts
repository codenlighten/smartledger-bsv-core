/**
 * The Transaction module.
 *
 * Mirrors what the JavaScript did — `module.exports = require('./transaction')`
 * then five `module.exports.X = ...` lines — which MUTATES the Transaction
 * constructor rather than building a new object. `export =` cannot express
 * assign-then-augment, so the mutations are written out and the five members
 * are declared optional on TransactionConstructor: they exist only once this
 * barrel has run, and `require('./transaction')` directly does not get them.
 */
import Transaction = require('./transaction')
import Input = require('./input')
import Output = require('./output')
import UnspentOutput = require('./unspentoutput')
import Signature = require('./signature')
import Sighash = require('./sighash')

Transaction.Input = Input
Transaction.Output = Output
Transaction.UnspentOutput = UnspentOutput
Transaction.Signature = Signature
Transaction.Sighash = Sighash

export = Transaction
