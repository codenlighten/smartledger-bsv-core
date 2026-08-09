/**
 * Previously this module required the package root and registered itself onto
 * it (`bsv.Mnemonic = require('./mnemonic')`), which made the library depend
 * on its own entry point. The registration was redundant — index assigns
 * bsv.Mnemonic itself — so this is a plain re-export.
 */
import Mnemonic = require('./mnemonic')

export = Mnemonic
