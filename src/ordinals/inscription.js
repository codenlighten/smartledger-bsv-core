'use strict'
/**
 * 1Sat Ordinals inscriptions.
 *
 * An inscription is content (a content-type + a body) carried on a 1-satoshi output
 * behind an inert data envelope, appended to a normal locking script (P2PKH by
 * default). The envelope is never executed, so spending is controlled entirely by the
 * base lock while the inscription rides on the satoshi:
 *
 *   <lockingScript>
 *   OP_FALSE OP_IF
 *     "ord"
 *     OP_1 <contentType>
 *     OP_0 <content>
 *   OP_ENDIF
 *
 * This matches the widely-used 1Sat Ordinals format (js-1sat-ord).
 */
const Script = require('../script')
const Opcode = require('../opcode')
const Address = require('../address')
const Output = require('../transaction/output')

const ORD = Buffer.from('ord', 'utf8')

/** Describe a rejected value for an error message, without dumping its contents. */
function typeName (v) {
  if (v === null) return 'null'
  if (v === undefined) return 'undefined'
  if (Array.isArray(v)) return 'an array'
  const t = typeof v
  return (t === 'object' ? 'an ' : 'a ') + t
}

/**
 * Coerce a caller-supplied field to bytes.
 *
 * Only strings and Buffers are accepted. Everything else is rejected rather than run
 * through `String(v)`: an inscription is permanent, and stringifying an object writes
 * the literal text `[object Object]` to the chain, which is never what the caller meant.
 */
function toBuf (v, name) {
  if (Buffer.isBuffer(v)) return v
  if (typeof v === 'string') return Buffer.from(v, 'utf8')
  throw new Error(name + ' must be a string or Buffer, got ' + typeName(v))
}

/** Fields callers reach for when they mean `content`; named back to them on error. */
const CONTENT_ALIASES = ['data', 'body', 'payload', 'text', 'message']

/** Resolve a base locking script from a Script, an Address, or an address string. */
function resolveLock (params) {
  const hasLock = params.lock != null
  const hasAddress = params.address != null

  // `lock` used to win silently. Two different owners in one call is a mistake worth
  // surfacing, not resolving by precedence.
  if (hasLock && hasAddress) {
    throw new Error('buildInscription accepts `lock` or `address`, not both — they name ' +
      'different owners and one would be silently ignored')
  }

  if (hasLock) {
    let lock
    if (params.lock instanceof Script) lock = params.lock
    else if (Buffer.isBuffer(params.lock)) lock = Script.fromBuffer(params.lock)
    else if (typeof params.lock === 'string') lock = Script.fromHex(params.lock)
    else throw new Error('lock must be a Script, Buffer, or hex string, got ' + typeName(params.lock))

    // An empty base lock leaves nothing but the inert envelope, and the envelope is
    // skipped at execution — so whatever the spender pushes is the final stack and the
    // ordinal is anyone-can-spend. Only a caller appending the envelope to a lock it
    // supplies itself (as ordlock.js does) legitimately wants this.
    if (!lock.chunks.length && !params.allowEmptyLock) {
      throw new Error('lock is empty: the inscription would carry no locking script at ' +
        'all and the ordinal would be spendable by anyone. Pass a real lock, or ' +
        '{ allowEmptyLock: true } if you are appending this envelope to your own script')
    }
    return lock
  }

  if (hasAddress) {
    const addr = (params.address instanceof Address)
      ? params.address
      : Address.fromString(String(params.address))
    return Script.buildPublicKeyHashOut(addr)
  }

  throw new Error('buildInscription requires an address or a lock script')
}

/**
 * Build a 1Sat Ordinals inscription locking script: a base lock followed by the
 * inert `OP_FALSE OP_IF ... OP_ENDIF` envelope carrying the content.
 *
 * `content` is required. An inscription with no body is a well-formed script that
 * inscribes nothing, so omitting it throws rather than silently producing one; pass an
 * explicit `''` if an empty payload is genuinely what you want.
 *
 * @param {object} params
 * @param {string|Buffer} params.content        the inscription body (required)
 * @param {string|Buffer} [params.contentType]  e.g. 'text/plain', 'image/png'.
 *   Defaults to 'text/plain' for string content; required for Buffer content, which
 *   carries no hint about what it is.
 * @param {Script|Buffer|string} [params.lock]  base locking script (mutually exclusive
 *   with `address`)
 * @param {Address|string} [params.address]     P2PKH owner (mutually exclusive with `lock`)
 * @param {boolean} [params.allowEmptyLock]     permit an empty base lock; see resolveLock
 * @returns {Script} the full inscription locking script
 */
function buildInscription (params) {
  params = params || {}
  const lock = resolveLock(params)

  if (params.content == null) {
    const alias = CONTENT_ALIASES.filter(function (k) { return params[k] != null })[0]
    throw new Error('buildInscription requires `content`' +
      (alias ? ' — received `' + alias + '`, which is not read' : '') +
      '. Omitting it would inscribe an empty payload; pass content: \'\' if that is intended')
  }
  const content = toBuf(params.content, 'content')

  let contentType
  if (params.contentType == null) {
    // A Buffer is opaque — defaulting it to text/plain mislabels binary content on a
    // permanent record, so make the caller declare it.
    if (Buffer.isBuffer(params.content)) {
      throw new Error('contentType is required when content is a Buffer (e.g. ' +
        "'image/png', 'application/octet-stream') — it cannot be inferred from bytes")
    }
    contentType = Buffer.from('text/plain', 'utf8')
  } else {
    contentType = toBuf(params.contentType, 'contentType')
    if (!contentType.length) throw new Error('contentType must not be empty')
  }

  // Clone the base lock so we never mutate the caller's Script.
  const s = Script.fromBuffer(lock.toBuffer())
  s.add(Opcode.OP_FALSE)
  s.add(Opcode.OP_IF)
  s.add(ORD)
  s.add(Opcode.OP_1)
  s.add(contentType)
  s.add(Opcode.OP_0)
  s.add(content)
  s.add(Opcode.OP_ENDIF)
  return s
}

function chunkIsOp (chunk, opcodenum) {
  return chunk && chunk.opcodenum === opcodenum && (chunk.buf == null)
}

/**
 * Parse a 1Sat Ordinals inscription out of a locking script.
 *
 * The 1Sat spec allows the locking script to be *prepended or appended* to the
 * envelope ("A locking script (typically P2PKH) is then prepended/appended to the
 * inscription script, optionally separated by OP_CODESEPARATOR"). `lock` is therefore
 * the whole script minus the envelope, in script order — not merely what precedes it.
 * A separating OP_CODESEPARATOR is kept, because it is genuinely part of the script
 * that runs and affects the sighash.
 *
 * @param {Script|Buffer|string} script
 * @returns {null|{ contentType: string, content: Buffer, contentText: string, lock: Script }}
 *   null if the script carries no inscription envelope.
 */
function parseInscription (script) {
  const s = (script instanceof Script)
    ? script
    : Buffer.isBuffer(script)
      ? Script.fromBuffer(script)
      : Script.fromHex(script)
  const chunks = s.chunks

  // Find `OP_FALSE OP_IF "ord"`.
  let start = -1
  for (let i = 0; i + 2 < chunks.length; i++) {
    if (chunkIsOp(chunks[i], Opcode.OP_FALSE) &&
        chunkIsOp(chunks[i + 1], Opcode.OP_IF) &&
        chunks[i + 2].buf && chunks[i + 2].buf.equals(ORD)) {
      start = i
      break
    }
  }
  if (start === -1) return null

  // Walk fields after "ord" until OP_ENDIF: OP_1 => content-type, OP_0 => body.
  let contentType = Buffer.alloc(0)
  let content = Buffer.alloc(0)
  let end = chunks.length // index of OP_ENDIF, or past the end if the envelope is unterminated
  for (let j = start + 3; j < chunks.length; j++) {
    const c = chunks[j]
    if (chunkIsOp(c, Opcode.OP_ENDIF)) { end = j; break }
    if (chunkIsOp(c, Opcode.OP_1) && chunks[j + 1] && chunks[j + 1].buf) {
      contentType = chunks[j + 1].buf; j++
    } else if (chunkIsOp(c, Opcode.OP_0) && chunks[j + 1] && chunks[j + 1].buf) {
      content = chunks[j + 1].buf; j++
    }
  }

  // The lock is everything outside the envelope. Taking only what precedes it dropped
  // the lock entirely for the spec-legal appended form, reporting an owned ordinal as
  // having no locking script at all.
  const lock = new Script()
  for (let k = 0; k < start; k++) lock.chunks.push(chunks[k])
  for (let m = end + 1; m < chunks.length; m++) lock.chunks.push(chunks[m])

  return {
    contentType: contentType.toString('utf8'),
    content,
    contentText: content.toString('utf8'),
    lock
  }
}

/** True if the script carries an inscription envelope. */
function isInscription (script) {
  try { return parseInscription(script) !== null } catch (e) { return false }
}

/**
 * Build the 1-satoshi Transaction.Output carrying an inscription.
 * @param {object} params           as buildInscription, plus:
 * @param {number} [params.satoshis]  defaults to 1 (the 1Sat Ordinals convention)
 * @returns {Transaction.Output}
 */
function createInscriptionOutput (params) {
  params = params || {}
  const satoshis = params.satoshis != null ? params.satoshis : 1
  // Output rejects negatives and fractions, but 0 and the string '1' slipped through:
  // a 0-sat output carries no ordinal at all.
  if (typeof satoshis !== 'number' || !Number.isInteger(satoshis) || satoshis < 1) {
    throw new Error('satoshis must be a positive integer (1 for a standard 1Sat ordinal)')
  }
  return new Output({
    script: buildInscription(params),
    satoshis
  })
}

module.exports = {
  buildInscription,
  parseInscription,
  isInscription,
  createInscriptionOutput
}
