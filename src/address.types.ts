/**
 * Shape of Address, declared separately so modules inside the
 * address <-> publickey <-> privatekey and script <-> transaction cycles can
 * refer to it as a TYPE without adding a runtime import edge.
 */
import type { Network } from './networks.types'

export type AddressType = 'pubkeyhash' | 'scripthash'

/** The normalized form produced by the _transform* helpers. */
export interface AddressInfo {
  hashBuffer?: Buffer
  /**
   * May be UNRESOLVED. `_transformScript` passes through whatever
   * `Script#getAddressInfo` recovered, which can be a network name or version
   * byte rather than a Network object; the Address constructor resolves it.
   * Typing this as `Network` alone would be a claim the producers do not meet.
   */
  network?: Network | string | number | undefined
  type?: AddressType
}

export interface Address {
  readonly hashBuffer: Buffer
  readonly network: Network
  readonly type: AddressType

  _classifyArguments: (data: unknown, network?: unknown, type?: AddressType) => AddressInfo
  isPayToPublicKeyHash: () => boolean
  isPayToScriptHash: () => boolean
  toBuffer: () => Buffer
  toHex: () => string
  toObject: () => Record<string, unknown>
  toJSON: () => Record<string, unknown>
  inspect: () => string
  toString: () => string
}

export interface AddressConstructor {
  new (data: unknown, network?: unknown, type?: AddressType): Address
  (data: unknown, network?: unknown, type?: AddressType): Address

  PayToPublicKeyHash: 'pubkeyhash'
  PayToScriptHash: 'scripthash'

  createMultisig: (publicKeys: unknown[], threshold: number, network?: unknown) => Address
  fromPublicKey: (data: unknown, network?: unknown) => Address
  fromPrivateKey: (privateKey: import('./privatekey.types').PrivateKey, network?: unknown) => Address
  fromPublicKeyHash: (hash: Buffer, network?: unknown) => Address
  fromScriptHash: (hash: Buffer, network?: unknown) => Address
  payingTo: (script: import('./script/script.types').Script, network?: unknown) => Address
  fromScript: (script: import('./script/script.types').Script, network?: unknown) => Address
  fromBuffer: (buffer: Buffer, network?: unknown, type?: AddressType) => Address
  fromHex: (hex: string, network?: unknown, type?: AddressType) => Address
  fromString: (str: string, network?: unknown, type?: AddressType) => Address
  fromObject: (obj: Record<string, unknown>) => Address
  getValidationError: (data: unknown, network?: unknown, type?: AddressType) => Error | undefined
  isValid: (data: unknown, network?: unknown, type?: AddressType) => boolean

  _transformHash: (hash: Buffer) => AddressInfo
  _transformObject: (data: Record<string, unknown>) => AddressInfo
  _classifyFromVersion: (buffer: Buffer) => AddressInfo
  _transformBuffer: (buffer: Buffer, network?: unknown, type?: AddressType) => AddressInfo
  _transformPublicKey: (pubkey: unknown) => AddressInfo
  _transformScript: (script: import('./script/script.types').Script, network?: unknown) => AddressInfo
  _transformString: (data: string, network?: unknown, type?: AddressType) => AddressInfo
}
