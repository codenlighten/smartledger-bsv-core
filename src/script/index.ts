/**
 * The Script module.
 *
 * Mirrors what the JavaScript did — `module.exports = require('./script')`
 * then `module.exports.Interpreter = require('./interpreter')` — which
 * MUTATES the Script constructor rather than building a new object. `export =`
 * cannot express assign-then-augment, so the mutation is written out and
 * `Interpreter` is declared on ScriptConstructor.
 */
import Script = require('./script')
import Interpreter = require('./interpreter')

Script.Interpreter = Interpreter

export = Script
