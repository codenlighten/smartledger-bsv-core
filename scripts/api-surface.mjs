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

function surface (bsv) {
  const rows = {}
  const walk = (obj, prefix, depth) => {
    if (depth > 2) return
    for (const k of Object.keys(obj).sort()) {
      if (k.startsWith('_')) continue
      let v
      try { v = obj[k] } catch { continue }
      const p = `${prefix}.${k}`
      const t = typeof v
      if (t === 'function') {
        rows[p] = 'function'
        for (const sk of Object.keys(v).sort()) {
          if (sk.startsWith('_')) continue
          let sv
          try { sv = v[sk] } catch { continue }
          rows[`${p}.${sk}`] = typeof sv
        }
      } else if (v && t === 'object') {
        rows[p] = 'namespace'
        walk(v, p, depth + 1)
      } else {
        rows[p] = t
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
