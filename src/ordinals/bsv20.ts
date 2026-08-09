'use strict'
/**
 * BSV-20 / BSV-21 fungible-token inscriptions.
 *
 * A BSV-20 token is a JSON payload (content-type `application/bsv-20`) carried inside an
 * ordinary 1Sat Ordinals inscription envelope on a 1-satoshi output. The token amount is
 * per-UTXO; an indexer tracks balances by replaying deploy / mint / transfer operations.
 * This module builds and parses those payloads — the on-chain plumbing is just an
 * inscription (see ./inscription), so a token output is a normal P2PKH-owned 1-sat output.
 *
 * Two protocol eras are supported:
 *   v1  (ticker-based)  deploy / mint / transfer keyed by a 1–4 byte `tick`.
 *   v2 / BSV-21 (id-based)  `deploy+mint` a supply in one step; transfer by `id`
 *                           (the deploy outpoint, `<txid>_<vout>`).
 *
 * Amounts (`amt`, `max`, `lim`) are INTEGER STRINGS — they routinely exceed 2^53, so they
 * are never coerced to JS numbers. `dec` (decimals, 0–18) scales display only.
 */
import inscription = require('./inscription')
import Script = require('../script')
import Output = require('../transaction/output')
import type { Bsv20Payload, Bsv20Params, Bsv20Input } from './types'

const CONTENT_TYPE = 'application/bsv-20'
const MAX_DEC = 18

// "Amounts in BSV-21: strings representing uint64" — amt/max/lim are bounded by 2^64-1.
// A larger value is emitted happily by JSON but rejected by indexers, burning the tokens.
const MAX_UINT64 = '18446744073709551615'

/** A non-negative integer string (no sign, no decimal point). */
function isIntString (v: unknown): v is string { return typeof v === 'string' && /^\d+$/.test(v) }

/** True if the CANONICAL decimal string `s` is greater than 2^64-1. */
function exceedsUint64 (s: string) {
  return s.length > MAX_UINT64.length || (s.length === MAX_UINT64.length && s > MAX_UINT64)
}

/** Normalize an amount-like field to a CANONICAL non-negative integer string (no leading zeros). */
function normInt (v: unknown, name: string) {
  let s
  if (typeof v === 'number') {
    if (!Number.isInteger(v) || v < 0) throw new Error(name + ' must be a non-negative integer')
    // Beyond 2^53 a JS number is already an approximation, so String(v) would silently
    // emit a *different* amount than the caller believes they passed.
    if (v > Number.MAX_SAFE_INTEGER) {
      throw new Error(name + ' exceeds Number.MAX_SAFE_INTEGER and would lose precision — ' +
        'pass it as a string')
    }
    s = String(v)
  } else if (isIntString(v)) {
    // Strip leading zeros ("007" -> "7", "000" -> "0") so the emitted payload is canonical
    // and not rejected by indexers that expect canonical decimal integers.
    s = v.replace(/^0+(?=\d)/, '')
  } else {
    throw new Error(name + ' must be a non-negative integer (string or number)')
  }
  if (exceedsUint64(s)) {
    throw new Error(name + ' exceeds the uint64 maximum (' + MAX_UINT64 + ')')
  }
  return s
}

/** Normalize a strictly-positive amount (mint/transfer/supply must move > 0). */
function normPositive (v: unknown, name: string) {
  const s = normInt(v, name)
  if (!/[1-9]/.test(s)) throw new Error(name + ' must be greater than zero')
  return s
}

/** Validate a v1 ticker: 1–4 UTF-8 bytes. */
function assertTick (tick: unknown) {
  if (typeof tick !== 'string' || !tick.length) throw new Error('tick is required')
  if (Buffer.byteLength(tick, 'utf8') > 4) throw new Error('tick must be 1–4 UTF-8 bytes')
  return tick
}

/** Normalize `dec` (decimals) to a string in 0…18. */
function normDec (dec: unknown) {
  const d: number = typeof dec === 'string' ? Number(dec) : (dec as number)
  if (!Number.isInteger(d) || d < 0 || d > MAX_DEC) throw new Error('dec must be an integer 0…' + MAX_DEC)
  return String(d)
}

const OUTPOINT_RE = /^[0-9a-fA-F]{64}_\d+$/

/** Validate a BSV-21 token id: `<64-hex-txid>_<vout>`. */
function assertId (id: unknown) {
  if (typeof id !== 'string' || !OUTPOINT_RE.test(id)) {
    throw new Error('id must be "<txid>_<vout>" (64-hex txid, underscore, output index)')
  }
  return id
}

/**
 * Validate a free-text field (`sym`). Rejects non-strings rather than running them through
 * `String()`, which wrote the literal text `[object Object]` into a permanent payload.
 */
function assertText (v: unknown, name: string) {
  if (typeof v !== 'string') {
    const t = v === null ? 'null' : Array.isArray(v) ? 'an array' : (typeof v === 'object' ? 'an ' : 'a ') + typeof v
    throw new Error(name + ' must be a string, got ' + t)
  }
  if (!v.length) throw new Error(name + ' must not be empty')
  return v
}

/** Validate `icon`, which the spec defines as an outpoint reference (`<txid>_<vout>`). */
function assertIcon (v: unknown) {
  const icon = assertText(v, 'icon')
  if (!OUTPOINT_RE.test(icon)) {
    throw new Error('icon must be an outpoint reference "<txid>_<vout>" (64-hex txid, ' +
      'underscore, output index)')
  }
  return icon
}

/** Wrap a BSV-20 JSON payload in an inscription locking script (P2PKH owner by default). */
function buildBsv20 (payload: Bsv20Payload, params?: Bsv20Params) {
  params = params || {}
  return inscription.buildInscription({
    lock: params.lock,
    address: params.address,
    contentType: params.contentType || CONTENT_TYPE,
    content: JSON.stringify(payload)
  })
}

/**
 * Deploy a v1 (ticker) token: fix its ticker, max supply, per-mint limit, and decimals.
 * @param {object} params { tick, max, lim?, dec?, address|lock, contentType? }
 * @returns {Script}
 */
function buildDeploy (params?: Bsv20Params) {
  params = params || {}
  const p: Bsv20Payload = { p: 'bsv-20', op: 'deploy', tick: assertTick(params.tick), max: normPositive(params.max, 'max') }
  // `lim` is "0 or omitted = unlimited" per the spec, so 0 is a meaningful value here and
  // must not be rejected the way a zero `max`/`amt` is.
  if (params.lim != null) p.lim = normInt(params.lim, 'lim')
  if (params.dec != null) p.dec = normDec(params.dec)
  return buildBsv20(p, params)
}

/**
 * Mint an amount of a v1 (ticker) token.
 * @param {object} params { tick, amt, address|lock, contentType? }
 * @returns {Script}
 */
/**
 * Name the token an operation acts on: `tick` (v1) or `id` (BSV-21), never both.
 * Passing both used to silently drop the `tick`, which is the wrong token, not a preference.
 */
function assignToken (p: Bsv20Payload, params: Bsv20Params, op: string) {
  const hasTick = params.tick != null
  const hasId = params.id != null
  if (hasTick && hasId) {
    throw new Error(op + ' names a token by `tick` (v1) or `id` (BSV-21), not both')
  }
  if (!hasTick && !hasId) {
    throw new Error(op + ' requires `tick` (v1) or `id` (BSV-21)')
  }
  if (hasId) p.id = assertId(params.id)
  else p.tick = assertTick(params.tick)
  return p
}

/** Reject `amt` on the operations the spec says must not carry one. */
function assertNoAmt (params: Bsv20Params, op: string) {
  if (params.amt != null) {
    throw new Error(op + ' must not carry an amt — the specification forbids it, and a ' +
      'payload that does is discarded')
  }
}

function buildMint (params?: Bsv20Params) {
  params = params || {}
  // `{p, op, tick|id, amt}` — the token first, then the amount.
  const p: Bsv20Payload = { p: 'bsv-20', op: 'mint' }
  assignToken(p, params, 'mint')
  p.amt = normPositive(params.amt, 'amt')
  return buildBsv20(p, params)
}

/**
 * Transfer an amount of a token. Provide `tick` (v1) OR `id` (v2 / BSV-21).
 * @param {object} params { tick?|id?, amt, address|lock, contentType? }
 * @returns {Script}
 */
function buildTransfer (params?: Bsv20Params) {
  params = params || {}
  const p: Bsv20Payload = { p: 'bsv-20', op: 'transfer', amt: normPositive(params.amt, 'amt') }
  assignToken(p, params, 'transfer')
  return buildBsv20(p, params)
}

/**
 * Burn an amount of a BSV-21 token: `{p, op:'burn', id, amt}`.
 *
 * BSV-21 (id-based) only — the specification defines `burn` under BSV-21, so there is no
 * ticker form. To retire v1 supply, transfer it to an unspendable output instead.
 *
 * @param {object} params { id, amt, address|lock, contentType? }
 * @returns {Script}
 */
function buildBurn (params?: Bsv20Params) {
  params = params || {}
  if (params.tick != null) {
    throw new Error('burn is a BSV-21 operation and names its token by `id` (<txid>_<vout>), ' +
      'not `tick`')
  }
  const p: Bsv20Payload = { p: 'bsv-20', op: 'burn', id: assertId(params.id), amt: normPositive(params.amt, 'amt') }
  return buildBsv20(p, params)
}

/**
 * Deploy a BSV-21 token under an AUTHORITY rather than a fixed supply:
 * `{p, op:'deploy+auth', sym?, dec?, icon?}`.
 *
 * Unlike `deploy+mint`, no supply is created here — minting happens later via `buildMint`
 * against this deploy's outpoint, and requires an auth input. The spec is explicit that
 * `amt` must NOT be present.
 *
 * @param {object} params { sym?, dec?, icon?, address|lock, contentType? }
 * @returns {Script}
 */
function buildDeployAuth (params?: Bsv20Params) {
  params = params || {}
  assertNoAmt(params, 'deploy+auth')
  const p: Bsv20Payload = { p: 'bsv-20', op: 'deploy+auth' }
  if (params.dec != null) p.dec = normDec(params.dec)
  if (params.sym != null) p.sym = assertText(params.sym, 'sym')
  if (params.icon != null) p.icon = assertIcon(params.icon)
  return buildBsv20(p, params)
}

/**
 * Mint authority for a BSV-21 token: `{p, op:'auth', id}`.
 *
 * The output this locks carries the right to mint the token, and "can be split, combined,
 * or transferred to delegate minting authority". It carries no amount — `amt` is forbidden.
 *
 * @param {object} params { id, address|lock, contentType? }
 * @returns {Script}
 */
function buildAuth (params?: Bsv20Params) {
  params = params || {}
  assertNoAmt(params, 'auth')
  const p: Bsv20Payload = { p: 'bsv-20', op: 'auth', id: assertId(params.id) }
  return buildBsv20(p, params)
}

/**
 * Deploy + mint a BSV-21 (id-based) token supply in one operation.
 * @param {object} params { amt, dec?, sym?, icon?, address|lock, contentType? }
 * @returns {Script}
 */
function buildDeployMint (params?: Bsv20Params) {
  params = params || {}
  const p: Bsv20Payload = { p: 'bsv-20', op: 'deploy+mint', amt: normPositive(params.amt, 'amt') }
  if (params.dec != null) p.dec = normDec(params.dec)
  if (params.sym != null) p.sym = assertText(params.sym, 'sym')
  if (params.icon != null) p.icon = assertIcon(params.icon)
  return buildBsv20(p, params)
}

function outputFor (script: Script, satoshis?: number) {
  return new Output({ script, satoshis: satoshis != null ? satoshis : 1 })
}

/** 1-sat Output helpers mirroring the builders. */
function createDeployOutput (params?: Bsv20Params) { return outputFor(buildDeploy(params), params && params.satoshis) }
function createMintOutput (params?: Bsv20Params) { return outputFor(buildMint(params), params && params.satoshis) }
function createTransferOutput (params?: Bsv20Params) { return outputFor(buildTransfer(params), params && params.satoshis) }
function createDeployMintOutput (params?: Bsv20Params) { return outputFor(buildDeployMint(params), params && params.satoshis) }
function createBurnOutput (params?: Bsv20Params) { return outputFor(buildBurn(params), params && params.satoshis) }
function createDeployAuthOutput (params?: Bsv20Params) { return outputFor(buildDeployAuth(params), params && params.satoshis) }
function createAuthOutput (params?: Bsv20Params) { return outputFor(buildAuth(params), params && params.satoshis) }

/** Extract the JSON body from a locking script, a JSON string, a Buffer, or an object. */
function bodyOf (input: Bsv20Input) {
  if (input && typeof input === 'object' && !Buffer.isBuffer(input) && !(input instanceof Script)) {
    return input // already a parsed object
  }
  if (typeof input === 'string' && input.trim()[0] === '{') return input // raw JSON string
  const insc = inscription.parseInscription(input) // Script / Buffer / hex script
  return insc ? insc.contentText : null
}

/**
 * Required-field rules per operation, from the BSV-20 / BSV-21 specification.
 *
 * `tickOrId` means the operation must carry exactly one of `tick` (v1) or `id` (v2/BSV-21).
 * `noAmt` marks the operations the spec says must NOT carry an `amt` at all.
 */
const OP_RULES: Record<string, any> = {
  deploy: { need: ['tick', 'max'] },
  mint: { need: ['amt'], tickOrId: true },
  transfer: { need: ['amt'], tickOrId: true },
  'deploy+mint': { need: ['amt'] },
  'deploy+auth': { need: [], noAmt: true },
  auth: { need: ['id'], noAmt: true },
  burn: { need: ['id', 'amt'] }
}

/**
 * Is `v` a uint64 amount as it may appear ON CHAIN? Leading zeros are tolerated here even
 * though the builder emits canonical values: this reads other people's payloads, and a
 * non-canonical amount is still an amount.
 */
function isParsedAmount (v: unknown) {
  const s = typeof v === 'number' ? (Number.isInteger(v) && v >= 0 ? String(v) : null) : (isIntString(v) ? v : null)
  if (s == null) return false
  return !exceedsUint64(s.replace(/^0+(?=\d)/, ''))
}

/** Validate a parsed payload against the spec's per-operation field rules. */
function isValidPayload (obj: Bsv20Payload) {
  if (!obj || obj.p !== 'bsv-20' || typeof obj.op !== 'string') return false
  const rule = OP_RULES[obj.op]
  if (!rule) return false // unknown operation: we cannot vouch for it
  for (let i = 0; i < rule.need.length; i++) {
    if (obj[rule.need[i]] == null) return false
  }
  if (rule.tickOrId && (obj.tick == null) === (obj.id == null)) return false
  if (rule.noAmt && obj.amt != null) return false
  if (obj.tick != null) {
    if (typeof obj.tick !== 'string' || !obj.tick.length || Buffer.byteLength(obj.tick, 'utf8') > 4) return false
  }
  if (obj.id != null && (typeof obj.id !== 'string' || !OUTPOINT_RE.test(obj.id))) return false
  const amounts = ['amt', 'max', 'lim']
  for (let j = 0; j < amounts.length; j++) {
    if (obj[amounts[j]!] != null && !isParsedAmount(obj[amounts[j]!])) return false
  }
  if (obj.dec != null) {
    const d = typeof obj.dec === 'string' ? Number(obj.dec) : obj.dec
    if (!Number.isInteger(d) || d < 0 || d > MAX_DEC) return false
  }
  return true
}

/**
 * Parse a BSV-20 payload from a locking script (Script/Buffer/hex), a JSON string, or an
 * already-parsed object. Returns the payload object (with `p:'bsv-20'`) or null if the
 * input carries no valid BSV-20 inscription.
 *
 * "Valid" is enforced, not assumed: the operation must be one the spec defines and must
 * carry the fields that operation requires, with `tick`/`id`/amount/`dec` well-formed.
 * A payload this returns is one an indexer will act on; previously any JSON object with
 * `p: 'bsv-20'` and a string `op` was returned, including `{p:'bsv-20', op:'transfer'}`
 * with no amount and no token — which an indexer discards.
 *
 * @returns {null|{ p:'bsv-20', op:string, tick?:string, id?:string, amt?:string, max?:string, lim?:string, dec?:string, sym?:string, icon?:string }}
 */
function parseBsv20 (input: Bsv20Input) {
  try {
    const body = bodyOf(input)
    if (body == null) return null
    const obj = (typeof body === 'object') ? body : JSON.parse(body)
    return isValidPayload(obj) ? obj : null
  } catch (e) {
    return null
  }
}

/** True if the input carries a valid BSV-20 inscription (see parseBsv20 for what that means). */
function isBsv20 (input: Bsv20Input) { return parseBsv20(input) !== null }

export = {
  CONTENT_TYPE,
  buildDeploy,
  buildMint,
  buildTransfer,
  buildDeployMint,
  buildBurn,
  buildDeployAuth,
  buildAuth,
  createDeployOutput,
  createMintOutput,
  createTransferOutput,
  createDeployMintOutput,
  createBurnOutput,
  createDeployAuthOutput,
  createAuthOutput,
  parseBsv20,
  isBsv20
}
