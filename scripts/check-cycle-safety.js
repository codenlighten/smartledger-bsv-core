#!/usr/bin/env node
'use strict'

/**
 * Guard: no module may DEREFERENCE a circular import during evaluation.
 *
 * The library has genuine import cycles (address <-> publickey, script <->
 * transaction, hdprivatekey <-> hdpublickey, ...). They follow the domain
 * model — an Address is derived from a PublicKey, and a PublicKey yields an
 * Address — and are not going away. Cycles are not themselves the problem:
 * CommonJS resolves them, and ESM resolves them too, PROVIDED no module reads
 * a binding from the cycle while its own body is still executing. Under ESM
 * that binding can be in its temporal dead zone, and the read throws.
 *
 * So the invariant worth enforcing is not "no cycles" — that would mean
 * fighting the domain model — but "no evaluation-time dereference of a cyclic
 * import".
 *
 * WHY THIS IS A STATIC CHECK, not a load test: an earlier version of this
 * script loaded every module first in a fresh registry and asserted it did not
 * throw. That passes even when the hazard is present, because under CommonJS
 * the partner module has usually finished loading by the time the binding is
 * read. CommonJS load order simply does not model ESM's TDZ, so a runtime
 * probe cannot detect this. The check has to be static.
 */

const fs = require('fs')
const path = require('path')

const SRC = path.join(__dirname, '..', 'src')

function walk (dir) {
  const out = []
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) out.push(...walk(p))
    else if (/\.(js|ts)$/.test(e.name) && !e.name.endsWith('.d.ts')) out.push(p)
  }
  return out
}

/**
 * Named bindings: `const X = require('./y')` -> { X: resolvedPath }.
 * Used to know WHICH identifier refers to a cyclic module.
 */
function localImports (src, file) {
  const out = new Map()
  const re = /^\s*(?:const|let|var|import)\s+([A-Za-z_$][\w$]*)\s*=\s*require\((['"])(\.[^'"]+)\2\)/gm
  for (const m of src.matchAll(re)) {
    try {
      out.set(m[1], require.resolve(path.resolve(path.dirname(file), m[3])))
    } catch (e) { /* unresolvable: not ours to police */ }
  }
  return out
}

/**
 * EVERY relative require, named or not.
 *
 * The reachability graph must include edges the binding scan cannot see —
 * barrel files use `module.exports = require('./x')` with no identifier at
 * all, and missing those makes a real cycle look acyclic. That bug made an
 * earlier version of this check pass while the hazard was present.
 */
function allEdges (src, file) {
  const out = new Set()
  for (const m of src.matchAll(/require\((['"])(\.[^'"]+)\1\)/g)) {
    try {
      out.add(require.resolve(path.resolve(path.dirname(file), m[2])))
    } catch (e) { /* unresolvable */ }
  }
  return out
}

const files = walk(SRC)
const imports = new Map()
const edges = new Map()
for (const f of files) {
  const src = fs.readFileSync(f, 'utf8')
  imports.set(f, localImports(src, f))
  edges.set(f, allEdges(src, f))
}

/** Does `from` reach `to` by following imports? */
function reaches (from, to, seen = new Set()) {
  if (from === to) return true
  if (seen.has(from)) return false
  seen.add(from)
  for (const dep of edges.get(from) ?? new Set()) {
    if (reaches(dep, to, seen)) return true
  }
  return false
}

const problems = []

for (const file of files) {
  const src = fs.readFileSync(file, 'utf8')
  const binds = imports.get(file) ?? new Map()

  // Bindings whose module can reach back here — i.e. participate in a cycle.
  const cyclic = new Map()
  for (const [name, target] of binds) {
    if (reaches(target, file)) cyclic.set(name, target)
  }
  if (cyclic.size === 0) continue

  // Scan for a dereference of one of those bindings at module scope (brace
  // depth 0), which is evaluation time.
  //
  // Block comments are stripped first: JSDoc routinely writes things like
  // `bsv.Script.Interpreter.useGenesisLimits(...)` in prose, and counting that
  // as a dereference buries the real findings in noise.
  const stripped = src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
  let depth = 0
  stripped.split('\n').forEach((line, i) => {
    const atModuleScope = depth === 0
    for (const ch of line) {
      if (ch === '{') depth++
      else if (ch === '}') depth--
    }
    if (!atModuleScope) return
    const code = line.replace(/\/\/.*$/, '')
    if (/^\s*(?:const|let|var|import)\s+[\w$]+\s*=\s*require\(/.test(code)) return
    // A reference inside a function body on the same line is deferred to call
    // time, which is precisely the fix this check asks for — do not flag it.
    if (/=>|\bfunction\b/.test(code)) return
    for (const name of cyclic.keys()) {
      // `Name.member` or `Name(` at module scope reads the binding now.
      if (new RegExp(`\\b${name}\\s*[.(]`).test(code)) {
        problems.push({
          file: path.relative(SRC, file),
          line: i + 1,
          binding: name,
          code: code.trim().slice(0, 90)
        })
      }
    }
  })
}

if (problems.length > 0) {
  console.error(`\nFAIL: ${problems.length} evaluation-time dereference(s) of a circular import.\n`)
  console.error('These work under CommonJS but can throw under ESM, where the binding')
  console.error('may still be in its temporal dead zone. Move the read inside the')
  console.error('function that needs it.\n')
  for (const p of problems) {
    console.error(`  ${p.file}:${p.line}  reads '${p.binding}'`)
    console.error(`    ${p.code}`)
  }
  process.exit(1)
}

console.log(`cycle-safety: OK — no evaluation-time dereference of a circular import (${files.length} modules)`)
