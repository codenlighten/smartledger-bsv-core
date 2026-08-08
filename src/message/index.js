// Previously this module required the package root and registered itself onto
// it (`bsv.Message = require('./message')`), which made lib/ depend on index.js.
// The registration was redundant — index.js assigns bsv.Message itself — so
// this is now a plain re-export.
module.exports = require('./message')
