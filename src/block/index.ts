/**
 * The Block module.
 *
 * Mirrors the JavaScript: `module.exports = require('./block')` then two
 * `module.exports.X =` lines, which MUTATE the Block constructor rather than
 * building a new object. `export =` cannot express assign-then-augment, so the
 * mutations are written out and the two members are declared optional on
 * BlockConstructor — they exist only once this barrel has run.
 */
import Block = require('./block')
import BlockHeader = require('./blockheader')
import MerkleBlock = require('./merkleblock')

Block.BlockHeader = BlockHeader
Block.MerkleBlock = MerkleBlock

export = Block
