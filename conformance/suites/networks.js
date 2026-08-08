'use strict'

/**
 * Network registry, including the regtest/stn toggles.
 *
 * WHY THIS SUITE EXISTS: `testnet.cashAddrPrefixArray` threw whenever STN was
 * enabled (`STN.cashAddrPrefixToArray is not a function`) — a live bug in
 * @smartledger/bsv 7.5.5, fixed there in 7.5.6 and in bsv-core. Nothing caught
 * it because nothing exercised the toggles.
 *
 * FIVE properties on testnet are toggle-sensitive getters, not data fields:
 * port, networkMagic, dnsSeeds, cashAddrPrefix and cashAddrPrefixArray. They
 * share a shape, so they share the failure mode — one of them was broken and
 * the other four were simply never called in a state that would have shown it.
 * This suite reads all five in all three states.
 *
 * STATE IS GLOBAL. enableRegtest/enableStn mutate the shared testnet object,
 * so every case restores the default in a finally. Without that a failure
 * mid-case would leak a toggle into every later case in the run.
 */

/** Read every toggle-sensitive getter, plus the stable fields for contrast. */
function readNetwork (net) {
  return {
    name: net.name,
    // Stable across toggles.
    pubkeyhash: net.pubkeyhash,
    privatekey: net.privatekey,
    scripthash: net.scripthash,
    xpubkey: net.xpubkey,
    xprivkey: net.xprivkey,
    // Toggle-sensitive getters.
    port: net.port,
    networkMagic: net.networkMagic,
    dnsSeeds: net.dnsSeeds,
    cashAddrPrefix: net.cashAddrPrefix,
    cashAddrPrefixArray: net.cashAddrPrefixArray
  }
}

/** Run `fn` with a toggle applied, always restoring the default afterwards. */
function withToggle (bsv, toggle, fn) {
  try {
    if (toggle === 'regtest') bsv.Networks.enableRegtest()
    if (toggle === 'stn') bsv.Networks.enableStn()
    return fn()
  } finally {
    bsv.Networks.disableRegtest()
    bsv.Networks.disableStn()
  }
}

const cases = {}

for (const toggle of ['none', 'regtest', 'stn']) {
  cases[`testnet with ${toggle} enabled`] = (bsv) =>
    withToggle(bsv, toggle, () => readNetwork(bsv.Networks.testnet))

  // Each getter individually too: a single combined case would report one diff
  // for any change, and the point here is to know WHICH property moved.
  for (const prop of ['port', 'networkMagic', 'dnsSeeds', 'cashAddrPrefix', 'cashAddrPrefixArray']) {
    cases[`testnet.${prop} with ${toggle} enabled`] = (bsv) =>
      withToggle(bsv, toggle, () => bsv.Networks.testnet[prop])
  }
}

Object.assign(cases, {
  // The other networks are plain objects; they must NOT move when a toggle is
  // flipped, which is the other half of the contract.
  'livenet is unaffected by regtest': (bsv) =>
    withToggle(bsv, 'regtest', () => readNetwork(bsv.Networks.livenet)),
  'livenet is unaffected by stn': (bsv) =>
    withToggle(bsv, 'stn', () => readNetwork(bsv.Networks.livenet)),

  'toggles restore cleanly': (bsv) => {
    const before = readNetwork(bsv.Networks.testnet)
    withToggle(bsv, 'stn', () => bsv.Networks.testnet.cashAddrPrefixArray)
    withToggle(bsv, 'regtest', () => bsv.Networks.testnet.cashAddrPrefixArray)
    const after = readNetwork(bsv.Networks.testnet)
    return { restored: JSON.stringify(before) === JSON.stringify(after) }
  },

  // Registry lookups.
  'get by name': (bsv) => ['livenet', 'testnet', 'regtest', 'stn']
    .map((n) => { const net = bsv.Networks.get(n); return net != null ? net.name : null }),
  'get by pubkeyhash version byte': (bsv) => {
    const net = bsv.Networks.get(0x00, 'pubkeyhash')
    return net != null ? net.name : null
  },
  'get by scripthash version byte': (bsv) => {
    const net = bsv.Networks.get(0x05, 'scripthash')
    return net != null ? net.name : null
  },
  'get with an unknown argument': (bsv) => bsv.Networks.get('nonesuch') ?? null,
  'defaultNetwork is livenet': (bsv) => bsv.Networks.defaultNetwork.name,
  'mainnet aliases livenet': (bsv) => bsv.Networks.mainnet === bsv.Networks.livenet,

  // Documented inconsistency: every shipped definition declares `prefix`, and
  // addNetwork installs `alias` from data.alias — which none of them supply.
  'alias is absent on every built-in network': (bsv) =>
    ['livenet', 'testnet', 'regtest', 'stn'].map((n) => {
      const net = bsv.Networks.get(n)
      return { network: n, alias: net != null ? (net.alias ?? null) : null }
    })
})

module.exports = { name: 'networks', cases }
