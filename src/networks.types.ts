/**
 * Shapes for the network registry.
 *
 * Separate module because networks.ts uses `export =` to keep its CommonJS
 * require() shape, and TypeScript forbids an export assignment alongside
 * other exported members.
 */

/**
 * A network's parameters.
 *
 * Most fields are installed via JSUtil.defineImmutable, and the optional ones
 * only when the definition supplies them — hence the optionality here, which
 * reflects what is actually present rather than an idealized record.
 */
export interface Network {
  name: string
  /**
   * Set by addNetwork from `data.alias`. The shipped definitions declare
   * `prefix` instead and never supply `alias`, so this is genuinely absent on
   * every built-in network — an inconsistency preserved here rather than
   * papered over, because callers can observe it.
   */
  alias?: string
  prefix?: string
  pubkeyhash: number
  privatekey: number
  scripthash: number
  xpubkey: number
  xprivkey: number
  networkMagic?: Buffer
  port?: number
  dnsSeeds?: string[]
  cashAddrPrefix?: string
  cashAddrPrefixArray?: number[]
  toString: () => string
}

/** The literal form a network is declared in, before normalization. */
export interface NetworkData {
  name: string
  alias?: string
  prefix?: string
  pubkeyhash: number
  privatekey: number
  scripthash: number
  xpubkey: number
  xprivkey: number
  networkMagic?: number
  port?: number
  dnsSeeds?: string[]
  cashAddrPrefix?: string
  indexBy?: string[]
}
