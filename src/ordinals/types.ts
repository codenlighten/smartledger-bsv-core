/**
 * Shapes for 1Sat Ordinals: inscriptions, OrdLock listings, and BSV-20 tokens.
 *
 * A note on how much precision is appropriate here. The inscription envelope
 * and the OrdLock covenant are OUR formats — we build the scripts, so their
 * inputs are typed exactly. The BSV-20 payload is not: it is a JSON blob
 * defined by an external spec that adds fields independently of this library,
 * and typing it as a closed shape would make a spec-conformant token fail to
 * compile. So the token payloads keep an index signature and the builders type
 * only the fields they actually read.
 */
import type { Script } from '../script/script.types'
import type { Address } from '../address.types'
import type { PublicKey } from '../publickey.types'
import type { PrivateKey } from '../privatekey.types'
import type { Output, Transaction, UnspentOutputLike } from '../transaction/types'
import type { Network } from '../networks.types'

/** A locking script, or something that resolves to one. */
export type LockLike = Script | Buffer | string
/** A payment destination. */
export type AddressLike = Address | PublicKey | PrivateKey | string

// --- inscriptions ----------------------------------------------------------

export interface InscriptionParams {
  /**
   * The owner. `lock` and `address` are MUTUALLY EXCLUSIVE — passing both
   * throws rather than picking one, because they name different owners and the
   * loser would be silently ignored.
   */
  lock?: LockLike | undefined
  address?: AddressLike | undefined
  /**
   * Required in practice. Declared optional because the runtime check gives a
   * far better error than a missing-property one: it names the alias you used
   * instead (`data`, `body`, ...) and tells you to pass `content: ''` if an
   * empty payload really was intended.
   */
  content?: string | Buffer | undefined
  /**
   * Required when `content` is a Buffer: bytes carry no hint of their type,
   * and mislabelling is permanent.
   */
  contentType?: string | undefined
  /** Opt in to a lock that leaves nothing but the inert envelope. */
  allowEmptyLock?: boolean | undefined
  /** buildInscription probes for misspelled content aliases to report them. */
  [key: string]: unknown
}

export interface InscriptionOutputParams extends InscriptionParams {
  /** Defaults to 1. Must be a positive integer — a 0-sat output carries no
   *  ordinal at all. */
  satoshis?: number | undefined
}

export interface ParsedInscription {
  contentType: string
  content: Buffer
  /** Everything OUTSIDE the envelope, both before and after it. */
  lock: Script
}

// --- OrdLock ---------------------------------------------------------------

/** One leg of a listing's payout: seller, royalty, or marketplace fee. */
/**
 * A payment destination: Address, PublicKey or PrivateKey (both carry
 * toAddress()), or an address string.
 */
export type PayeeLike = Address | PublicKey | PrivateKey | string

/**
 * One leg of a listing's payout: seller, royalty, or marketplace fee.
 *
 * BOTH spellings of each field are accepted — `address`/`payTo` and
 * `satoshis`/`price` — so neither is required on its own. outputFromSpec
 * demands one of each at runtime and names both in the error.
 */
export interface PayOutputSpec {
  address?: PayeeLike | undefined
  payTo?: PayeeLike | undefined
  satoshis?: number | undefined
  price?: number | undefined
}

/** Anything resolvePayOutputs will turn into an Output. */
export type PayOutputLike = Output | Buffer | PayOutputSpec

/**
 * A 20-byte HASH160 owner commitment, or anything that yields one. A Buffer
 * here MUST be exactly 20 bytes — it is used as the hash directly.
 */
export type OwnerLike = Buffer | PayeeLike

export interface OrdLockParams {
  seller?: OwnerLike | undefined
  sellerAddress?: PayeeLike | undefined
  sellerPubKeyHash?: Buffer | undefined
  /** Priority order: payOutputs, then payOutput, then price + payTo. */
  payOutputs?: PayOutputLike[] | undefined
  payOutput?: PayOutputLike | undefined
  price?: number | undefined
  /**
   * Defaults to `seller` when omitted. A pre-built Output here is used
   * verbatim with ITS value, so `price` is not applied to it.
   */
  payTo?: PayeeLike | Output | undefined
  /** Appended after the primary payout, in order. */
  royalties?: PayOutputLike[] | undefined
  /** The ordinal being listed: inscription params, or a parsed inscription
   *  fed straight back in by parseOrdLock's re-verification step. */
  inscription?: InscriptionParams | ParsedInscription | undefined
}

/**
 * What parseOrdLock returns, and it is NOT a mirror of OrdLockParams — it is
 * what could be recovered from the script and independently re-verified.
 *
 * parseOrdLock rebuilds the listing from these terms and requires it to match
 * the input byte for byte before returning anything. Shape alone proves
 * nothing: a script with this arrangement of opcodes but no OP_PUSH_TX
 * covenant enforces no payment, and reporting a seller and a price for it
 * would invent a listing that does not exist.
 */
export interface ParsedOrdLock {
  seller: { pubKeyHash: Buffer, address: string }
  payOutputs: Array<{ satoshis: number, script: string, address: string | null }>
  /** The pinned payment bytes the covenant commits to. */
  payBlob: Buffer
  /** Sum of every payout leg — what a buyer must pay in total. */
  totalPrice: number
  inscription: { contentType: string, content: Buffer, contentText?: string } | null
}

/**
 * The spend-side helpers (listInscriptionOutput, purchase, cancel) all unlock
 * an existing OrdLock output, so they share one shape: the transaction being
 * built, which of its inputs is the covenant, and what that input is worth.
 */
export interface UnlockParams {
  /** The transaction spending the listing. Mutated in place. */
  spend?: Transaction | undefined
  inputIndex?: number | undefined
  lockingScript?: LockLike | undefined
  satoshis?: number | undefined
  privateKey?: PrivateKey | string | undefined
  sighashType?: number | undefined
  /** Pre-parsed terms, so the locking script is not parsed twice. */
  parsed?: ParsedOrdLock | undefined
  /** Which payout leg this spend satisfies, and how many there are. */
  payoutIndex?: number | undefined
  payoutCount?: number | undefined
  /** OP_PUSH_TX grind options, forwarded to Covenant.PushTx.grind. */
  grind?: number | Record<string, unknown> | undefined
  /** Run the interpreter over the result before returning it. */
  validate?: boolean | undefined
}

/**
 * A coin these helpers can spend: an outpoint in any of the three spellings
 * this library accepts, plus the locking script and the key to sign with.
 *
 * `satoshis` is required and checked, not defaulted: the amount is part of the
 * BIP-143 preimage, so a missing or NaN value produces a signature over the
 * wrong amount that fails only on-chain.
 */
export interface FundingCoin {
  txid?: string | undefined
  prevTxId?: string | Buffer | undefined
  outputIndex?: number | undefined
  vout?: number | undefined
  script: LockLike
  satoshis: number
  privateKey: PrivateKey
}

/** An outpoint alone, for inputs whose script and value are supplied separately. */
export interface OutpointLike {
  txid?: string | undefined
  prevTxId?: string | Buffer | undefined
  outputIndex?: number | undefined
  vout?: number | undefined
}

/** buildListingTx: assemble and sign a listing from an ordinal plus coins. */
export interface ListingTxParams {
  ordinal?: FundingCoin | undefined
  ordinalDestination?: PayeeLike | undefined
  listing?: FundingCoin | undefined
  payOutputs?: PayOutputLike[] | undefined
  funding?: FundingCoin[] | undefined
  changeAddress?: PayeeLike | undefined
  fee?: number | undefined
  grind?: number | Record<string, unknown> | undefined
}

/** buildPurchaseTx: the same, minus the ordinal — that comes from the listing. */
export type PurchaseTxParams = Omit<ListingTxParams, 'ordinal'>

export interface BuiltTx {
  tx: Transaction
  [key: string]: unknown
}

/** parseOrdLock's options: only the network the recovered address belongs to. */
export interface ParseOrdLockOptions {
  network?: Network | string | number | undefined
}

// --- BSV-20 ----------------------------------------------------------------

/**
 * A BSV-20 / BSV-21 JSON payload.
 *
 * Open on purpose. The fields below are the ones this library reads and
 * validates; the spec defines others and will define more, and a closed shape
 * would reject a valid token rather than pass it through.
 */
export interface Bsv20Payload {
  p: string
  op: string
  tick?: string
  id?: string
  amt?: string
  max?: string
  lim?: string
  dec?: string
  sym?: string
  icon?: string
  [key: string]: unknown
}

/** Inputs to the BSV-20 builders — the token fields plus inscription owner. */
export interface Bsv20Params extends Partial<Bsv20Payload> {
  lock?: LockLike | undefined
  address?: AddressLike | undefined
  satoshis?: number | undefined
  /** Overrides the default application/bsv-20 content type. */
  contentType?: string | undefined
}

/** What the parsers accept: a Script, an Output, or an inscription payload. */
export type Bsv20Input = Script | Output | Buffer | string
