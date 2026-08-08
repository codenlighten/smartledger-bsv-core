'use strict'
import _ = require('./util/_')

import JSUtil = require('./util/js')
import type { Network, NetworkData } from './networks.types'
const networks: Network[] = []
const networkMaps: Record<string, Network> = {}

/**
 * A network is merely a map containing values that correspond to version
 * numbers for each bitcoin network. Currently only supporting "livenet"
 * (a.k.a. "mainnet"), "testnet", "regtest" and "stn".
 * @constructor
 */
function Network (this: Network): void {}

Network.prototype.toString = function toString (this: Network): string {
  return this.name
}

/**
 * @function
 * @member Networks#get
 * Retrieves the network associated with a magic number or string.
 * @param {string|number|Network} arg
 * @param {string|Array} keys - if set, only check if the magic number associated with this name matches
 * @return Network
 */
function get (arg: string | number | Network, keys?: string | string[]): Network | undefined {
  if (~networks.indexOf(arg as Network)) {
    return arg as Network
  }
  if (keys != null) {
    const ks: string[] = _.isArray(keys) ? keys as string[] : [keys as string]
    for (let i = 0; i < networks.length; i++) {
      const network = networks[i] as Network
      const filteredNet = _.pick(network as unknown as Record<string, unknown>, ks)
      const netValues = _.values(filteredNet)
      if (~netValues.indexOf(arg)) {
        return network
      }
    }
    return undefined
  }
  return networkMaps[String(arg)]
}

/***
 * Derives an array from the given cashAddrPrefix to be used in the computation
 * of the address' checksum.
 *
 * @param {string} cashAddrPrefix Network cashAddrPrefix. E.g.: 'bitcoincash'.
 */
function cashAddrPrefixToArray (cashAddrPrefix: string): number[] {
  const result = []
  for (let i = 0; i < cashAddrPrefix.length; i++) {
    result.push(cashAddrPrefix.charCodeAt(i) & 31)
  }
  return result
}

/**
 * @function
 * @member Networks#add
 * Will add a custom Network
 * @param {Object} data
 * @param {string} data.name - The name of the network
 * @param {string} data.alias - The aliased name of the network
 * @param {Number} data.pubkeyhash - The publickey hash cashAddrPrefix
 * @param {Number} data.privatekey - The privatekey cashAddrPrefix
 * @param {Number} data.scripthash - The scripthash cashAddrPrefix
 * @param {Number} data.xpubkey - The extended public key magic
 * @param {Number} data.xprivkey - The extended private key magic
 * @param {Number} data.networkMagic - The network magic number
 * @param {Number} data.port - The network port
 * @param {Array}  data.dnsSeeds - An array of dns seeds
 * @return Network
 */
function addNetwork (data: NetworkData): Network {
  const network = new (Network as unknown as new () => Network)()

  JSUtil.defineImmutable(network, {
    name: data.name,
    alias: data.alias,
    pubkeyhash: data.pubkeyhash,
    privatekey: data.privatekey,
    scripthash: data.scripthash,
    xpubkey: data.xpubkey,
    xprivkey: data.xprivkey
  })

  const indexBy = data.indexBy ?? Object.keys(data)

  if (data.cashAddrPrefix != null) {
    _.extend(network, {
      cashAddrPrefix: data.cashAddrPrefix,
      cashAddrPrefixArray: cashAddrPrefixToArray(data.cashAddrPrefix)
    })
  }

  if (data.networkMagic != null) {
    _.extend(network, {
      networkMagic: JSUtil.integerAsBuffer(data.networkMagic)
    })
  }

  if (data.port != null) {
    _.extend(network, {
      port: data.port
    })
  }

  if (data.dnsSeeds != null) {
    _.extend(network, {
      dnsSeeds: data.dnsSeeds
    })
  }
  networks.push(network)
  indexNetworkBy(network, indexBy)
  return network
}

function indexNetworkBy (network: Network, keys: string[]): void {
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]
    if (key === undefined) continue
    const networkValue = (network as unknown as Record<string, unknown>)[key]
    if (!_.isUndefined(networkValue) && !_.isObject(networkValue)) {
      networkMaps[String(networkValue)] = network
    }
  }
}

function unindexNetworkBy (network: Network, values: string[]): void {
  for (let index = 0; index < values.length; index++) {
    const value = values[index]
    if (value === undefined) continue
    if (networkMaps[value] === network) {
      delete networkMaps[value] // eslint-disable-line @typescript-eslint/no-dynamic-delete
    }
  }
}

/**
 * @function
 * @member Networks#remove
 * Will remove a custom network
 * @param {Network} network
 */
function removeNetwork (network: Network): void {
  for (let i = 0; i < networks.length; i++) {
    if (networks[i] === network) {
      networks.splice(i, 1)
    }
  }
  unindexNetworkBy(network, Object.keys(networkMaps))
}

const networkMagic = {
  livenet: 0xe3e1f3e8,
  testnet: 0xf4e5f3f4,
  regtest: 0xdab5bffa,
  stn: 0xfbcec4f9
}

const dnsSeeds = [
  'seed.bitcoinsv.org',
  'seed.bitcoinunlimited.info'
]

const TESTNET = {
  PORT: 18333,
  NETWORK_MAGIC: networkMagic.testnet,
  DNS_SEEDS: dnsSeeds,
  PREFIX: 'testnet',
  CASHADDRPREFIX: 'bchtest'
}

const REGTEST = {
  PORT: 18444,
  NETWORK_MAGIC: networkMagic.regtest,
  DNS_SEEDS: [],
  PREFIX: 'regtest',
  CASHADDRPREFIX: 'bchreg'
}

const STN = {
  PORT: 9333,
  NETWORK_MAGIC: networkMagic.stn,
  DNS_SEEDS: ['stn-seed.bitcoinsv.io'],
  PREFIX: 'stn',
  CASHADDRPREFIX: 'bsvstn'
}

const liveNetwork = {
  name: 'livenet',
  alias: 'mainnet',
  prefix: 'bitcoin',
  cashAddrPrefix: 'bitcoincash',
  pubkeyhash: 0x00,
  privatekey: 0x80,
  scripthash: 0x05,
  xpubkey: 0x0488b21e,
  xprivkey: 0x0488ade4,
  networkMagic: networkMagic.livenet,
  port: 8333,
  dnsSeeds
}

// network magic, port, cashAddrPrefix, and dnsSeeds are overloaded by enableRegtest
const testNetwork = {
  name: 'testnet',
  prefix: TESTNET.PREFIX,
  cashAddrPrefix: TESTNET.CASHADDRPREFIX,
  pubkeyhash: 0x6f,
  privatekey: 0xef,
  scripthash: 0xc4,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  networkMagic: TESTNET.NETWORK_MAGIC
}

const regtestNetwork = {
  name: 'regtest',
  prefix: REGTEST.PREFIX,
  cashAddrPrefix: REGTEST.CASHADDRPREFIX,
  pubkeyhash: 0x6f,
  privatekey: 0xef,
  scripthash: 0xc4,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  networkMagic: REGTEST.NETWORK_MAGIC,
  port: REGTEST.PORT,
  dnsSeeds: [],
  indexBy: [
    'port',
    'name',
    'cashAddrPrefix',
    'networkMagic'
  ]
}
const stnNetwork = {
  name: 'stn',
  prefix: STN.PREFIX,
  cashAddrPrefix: STN.CASHADDRPREFIX,
  pubkeyhash: 0x6f,
  privatekey: 0xef,
  scripthash: 0xc4,
  xpubkey: 0x043587cf,
  xprivkey: 0x04358394,
  networkMagic: STN.NETWORK_MAGIC,
  indexBy: [
    'port',
    'name',
    'cashAddrPrefix',
    'networkMagic'
  ]
}
// Add configurable values for testnet/regtest

addNetwork(testNetwork)
addNetwork(stnNetwork)
addNetwork(regtestNetwork)
addNetwork(liveNetwork)

// get() returns Network | undefined; these four are registered above, so the
// assertions are safe and keep the exported constants non-optional.
const livenet = get('livenet') as Network
const regtest = get('regtest') as Network
const testnet = get('testnet') as Network
const stn = get('stn') as Network

Object.defineProperty(testnet, 'port', {
  enumerable: true,
  configurable: false,
  get: function (this: Network & { regtestEnabled?: boolean, stnEnabled?: boolean }) {
    if (this.regtestEnabled) {
      return REGTEST.PORT
    } else if (this.stnEnabled) {
      return STN.PORT
    } else {
      return TESTNET.PORT
    }
  }
})

Object.defineProperty(testnet, 'networkMagic', {
  enumerable: true,
  configurable: false,
  get: function (this: Network & { regtestEnabled?: boolean, stnEnabled?: boolean }) {
    if (this.regtestEnabled) {
      return JSUtil.integerAsBuffer(REGTEST.NETWORK_MAGIC)
    } else if (this.stnEnabled) {
      return JSUtil.integerAsBuffer(STN.NETWORK_MAGIC)
    } else {
      return JSUtil.integerAsBuffer(TESTNET.NETWORK_MAGIC)
    }
  }
})

Object.defineProperty(testnet, 'dnsSeeds', {
  enumerable: true,
  configurable: false,
  get: function (this: Network & { regtestEnabled?: boolean, stnEnabled?: boolean }) {
    if (this.regtestEnabled) {
      return REGTEST.DNS_SEEDS
    } else if (this.stnEnabled) {
      return STN.DNS_SEEDS
    } else {
      return TESTNET.DNS_SEEDS
    }
  }
})

Object.defineProperty(testnet, 'cashAddrPrefix', {
  enumerable: true,
  configurable: false,
  get: function (this: Network & { regtestEnabled?: boolean, stnEnabled?: boolean }) {
    if (this.regtestEnabled) {
      return REGTEST.CASHADDRPREFIX
    } else if (this.stnEnabled) {
      return STN.CASHADDRPREFIX
    } else {
      return TESTNET.CASHADDRPREFIX
    }
  }
})

Object.defineProperty(testnet, 'cashAddrPrefixArray', {
  enumerable: true,
  configurable: false,
  get: function (this: Network & { regtestEnabled?: boolean, stnEnabled?: boolean }) {
    if (this.regtestEnabled) {
      return cashAddrPrefixToArray(REGTEST.CASHADDRPREFIX)
    } else if (this.stnEnabled) {
      // BUG FIX: this read `STN.cashAddrPrefixToArray(...)`, but STN is a plain
      // data object with no such method, so reading this getter after
      // enableStn() threw `TypeError: STN.cashAddrPrefixToArray is not a
      // function`. The other two branches call the module-level function; this
      // one now does too. Present and reproducible in @smartledger/bsv 7.5.5.
      return cashAddrPrefixToArray(STN.CASHADDRPREFIX)
    } else {
      return cashAddrPrefixToArray(TESTNET.CASHADDRPREFIX)
    }
  }
})

/**
 * @function
 * @member Networks#enableRegtest
 * Will enable regtest features for testnet
 */
function enableRegtest (): void {
  (testnet as Network & { regtestEnabled?: boolean }).regtestEnabled = true
}

/**
 * @function
 * @member Networks#disableRegtest
 * Will disable regtest features for testnet
 */
function disableRegtest (): void {
  (testnet as Network & { regtestEnabled?: boolean }).regtestEnabled = false
}
/**
 * @function
 * @member Networks#enableStn
 * Will enable stn features for testnet
 */
function enableStn (): void {
  (testnet as Network & { stnEnabled?: boolean }).stnEnabled = true
}

/**
 * @function
 * @member Networks#disableStn
 * Will disable stn features for testnet
 */
function disableStn (): void {
  (testnet as Network & { stnEnabled?: boolean }).stnEnabled = false
}

/**
 * @namespace Networks
 */
const Networks = {
  add: addNetwork,
  remove: removeNetwork,
  defaultNetwork: livenet,
  livenet,
  mainnet: livenet,
  testnet,
  regtest,
  stn,
  get,
  enableRegtest,
  disableRegtest,
  enableStn,
  disableStn
}

export = Networks
