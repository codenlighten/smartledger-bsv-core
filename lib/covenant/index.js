'use strict'
/**
 * Covenant primitives — OP_PUSH_TX and the BIP-143 preimage helpers it needs.
 *
 * These live in core rather than under lib/smart_contract because they have two
 * independent consumers: the smart-contract tooling, and lib/ordinals (OrdLock
 * covenants). lib/ordinals previously reached sideways into lib/smart_contract
 * for them, which was the only dependency from core code into the application
 * layer and the one thing blocking a clean split of the two.
 *
 * Nothing here depends on anything above Script / Transaction / crypto.
 *
 * The old paths (lib/smart_contract/pushtx.js and
 * lib/smart_contract/covenant_helpers.js) remain as re-export shims, since deep
 * imports are public API via the package.json exports map.
 */

module.exports = {
  PushTx: require('./pushtx'),
  Helpers: require('./helpers')
}
