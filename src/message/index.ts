/**
 * Previously this module required the package root and registered itself onto
 * it (`bsv.Message = require('./message')`), which made the library depend on
 * its own entry point. The registration was redundant — index assigns
 * bsv.Message itself — so this is a plain re-export.
 */
import Message = require('./message')

export = Message
