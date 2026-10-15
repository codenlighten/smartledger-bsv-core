// Records the public API surface as a snapshot, so the 1.x stability promise in the README is
// a measured claim rather than an assertion. A 1.x release may ADD names; removing or
// re-typing one is a breaking change and this refuses it.
//
// Written when the package went 1.0.0: promising that a surface will not change shape without
// first knowing what is in it is a promise nobody can keep.
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..')
const SNAPSHOT = path.join(root, 'test', 'fixtures', 'api-surface.json')

// Own-property noise that carries no API meaning — but ONLY on a function, where these are
// intrinsic. A first version of this skipped `name` everywhere and silently dropped five real
// rows (bsv.Networks.livenet.name and its siblings), which is the failure this script exists to
// prevent, committed by the script itself.
const FN_SKIP = new Set(['length', 'name', 'prototype', 'constructor', 'caller', 'arguments', '__proto__', 'super_'])
const SKIP = new Set(['constructor', 'caller', 'arguments', '__proto__', 'super_'])

// A function is recorded WITH ITS ARITY, and prototype methods are recorded as `path#member`.
// Without both, this lock reported "nothing re-typed" through the 1.8.0 change that added an
// options parameter to Message#verify and its static — the exact shape of change the snapshot
// exists to notice, and the shape that had just been shown to matter: before 1.8.0 the option was
// accepted and IGNORED, so a build that wires a parameter and a build that drops it are
// indistinguishable to a caller until the behaviour is probed. The sibling package's lock has
// recorded arity since 1.0.0; this one now matches it.
// Descend only into a PLAIN namespace. A class instance (a BN constant, a Buffer) is a value, not
// a namespace: walking into one adds its internals as API rows — the first attempt at this
// descended into any object and produced 13,565 rows, most of them bn.js internals and wordlist
// entries. The sibling package's lock uses exactly this test.
// A Network is configuration rather than a value: its fields (`pubkeyhash`, `privatekey`,
// `xpubkey`, `networkMagic`) are load-bearing API, and the previous version of this script
// tracked them because it descended into every object. Named explicitly so they keep being
// tracked without also walking into bn.js instances, whose prototype carries 126 methods where
// Network's carries one. If the class is ever renamed, these rows disappear and this script fails
// with "removed", which is the right alarm.
function isNetworkConfig (v) {
  return v !== null && typeof v === 'object' && v.constructor && v.constructor.name === 'Network'
}

function isPlainNamespace (v) {
  if (v === null || typeof v !== 'object') return false
  if (Buffer.isBuffer(v) || Array.isArray(v)) return false
  const proto = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

function describe (v) {
  if (v === null) return 'null'
  if (Buffer.isBuffer(v)) return 'buffer'
  if (Array.isArray(v)) return 'array'
  const t = typeof v
  if (t === 'function') return `function(${v.length})`
  if (t === 'number' || t === 'string' || t === 'boolean') return t
  return 'object'
}

function surface (bsv) {
  const rows = {}
  const walk = (obj, prefix, depth) => {
    if (depth > 2) return
    for (const k of Object.keys(obj).sort()) {
      if (k.startsWith('_') || SKIP.has(k)) continue
      let v
      try { v = obj[k] } catch { continue }
      const p = `${prefix}.${k}`
      const t = typeof v
      if (t === 'function') {
        rows[p] = describe(v)
        for (const sk of Object.keys(v).sort()) {
          if (sk.startsWith('_') || FN_SKIP.has(sk)) continue
          let sv
          try { sv = v[sk] } catch { continue }
          // An object-valued static is a namespace and is walked, exactly as before: stopping at
          // `describe` here is what dropped the Networks rows.
          if ((isPlainNamespace(sv) || isNetworkConfig(sv)) && depth + 1 <= 2) {
            rows[`${p}.${sk}`] = 'namespace'
            walk(sv, `${p}.${sk}`, depth + 1)
          } else {
            rows[`${p}.${sk}`] = describe(sv)
          }
        }
        if (v.prototype && depth + 1 <= 2) {
          for (const m of Object.getOwnPropertyNames(v.prototype).sort()) {
            if (m.startsWith('_') || FN_SKIP.has(m)) continue
            const pd = Object.getOwnPropertyDescriptor(v.prototype, m)
            if (pd && pd.get) { rows[`${p}#${m}`] = 'getter'; continue }
            rows[`${p}#${m}`] = describe(pd ? pd.value : undefined)
          }
        }
      } else if (isPlainNamespace(v) || isNetworkConfig(v)) {
        rows[p] = 'namespace'
        walk(v, p, depth + 1)
      } else {
        rows[p] = describe(v)
      }
    }
  }
  walk(bsv, 'bsv', 0)
  return rows
}

const current = surface(require(path.join(root, 'dist', 'index.js')))
const update = process.argv.includes('--update')

if (update || !fs.existsSync(SNAPSHOT)) {
  fs.mkdirSync(path.dirname(SNAPSHOT), { recursive: true })
  fs.writeFileSync(SNAPSHOT, JSON.stringify(current, null, 2) + '\n')
  console.log(`api-surface: wrote ${Object.keys(current).length} names to ${path.relative(root, SNAPSHOT)}`)
  process.exit(0)
}

const before = JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8'))
const removed = Object.keys(before).filter((k) => !(k in current))
const retyped = Object.keys(before).filter((k) => k in current && before[k] !== current[k])
const added = Object.keys(current).filter((k) => !(k in before))

if (removed.length || retyped.length) {
  console.error('api-surface: this is a BREAKING change to the public surface.\n')
  for (const k of removed) console.error(`  removed  ${k}  (was ${before[k]})`)
  for (const k of retyped) console.error(`  retyped  ${k}  ${before[k]} -> ${current[k]}`)
  console.error('\nThe README promises these do not change shape within 1.x. Either restore them,')
  console.error('or make this a major and run: node scripts/api-surface.mjs --update')
  process.exit(1)
}

console.log(`api-surface: OK — ${Object.keys(current).length} names, ${added.length} added, nothing removed or re-typed.`)
if (added.length) {
  for (const k of added.slice(0, 20)) console.log(`  added  ${k}  (${current[k]})`)
  console.log('  additions are a minor; run --update to record them.')
}
