'use strict'

const fs = require('fs')
const path = require('path')
const { captureAsync, stringify } = require('./serialize')

const SUITES_DIR = path.join(__dirname, '..', 'suites')
const FIXTURES_DIR = path.join(__dirname, '..', 'fixtures')

/**
 * Load every suite module.
 *
 * A suite is `{ name, cases: { [caseName]: (bsv) => any } }`. Suites receive the
 * library as an argument and never require() it, which is the whole point: the
 * same suite runs against the current CommonJS library and against the
 * TypeScript rewrite without modification.
 */
function loadSuites (filter) {
  if (!fs.existsSync(SUITES_DIR)) return []
  const suites = fs.readdirSync(SUITES_DIR)
    .filter((f) => f.endsWith('.js'))
    .map((f) => {
      const suite = require(path.join(SUITES_DIR, f))
      if (!suite || typeof suite !== 'object') {
        throw new Error(`suite ${f} did not export an object`)
      }
      if (!suite.name) throw new Error(`suite ${f} is missing a name`)
      if (!suite.cases || typeof suite.cases !== 'object') {
        throw new Error(`suite ${f} is missing a cases object`)
      }
      if (suite.name !== path.basename(f, '.js')) {
        throw new Error(`suite ${f} declares name "${suite.name}"; must match its filename`)
      }
      return suite
    })
    .sort((a, b) => (a.name < b.name ? -1 : 1))

  return filter ? suites.filter((s) => s.name === filter) : suites
}

/** Run one suite against a library instance, returning `{ case: outcome }`. */
async function runSuite (suite, bsv) {
  const results = {}
  for (const caseName of Object.keys(suite.cases).sort()) {
    const fn = suite.cases[caseName]
    if (typeof fn !== 'function') {
      throw new Error(`${suite.name}: case "${caseName}" is not a function`)
    }
    results[caseName] = await captureAsync(() => fn(bsv))
  }
  return results
}

function fixturePath (name) {
  return path.join(FIXTURES_DIR, name + '.json')
}

function readFixture (name) {
  const p = fixturePath(name)
  if (!fs.existsSync(p)) return null
  return JSON.parse(fs.readFileSync(p, 'utf8'))
}

function writeFixture (name, data) {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true })
  fs.writeFileSync(fixturePath(name), stringify(data))
}

/**
 * Compare a fresh run against a recorded fixture.
 *
 * `errorMode` controls how strictly thrown errors are matched:
 *   'name' (default) — the error's `name` must match; wording may change.
 *   'full'           — name and message must both match exactly.
 *
 * Name-only is the right default across a reimplementation: rewording an error
 * is not a behavior change, but a rejection turning into a success is.
 */
function compare (expected, actual, errorMode) {
  errorMode = errorMode || 'name'
  const diffs = []
  const names = new Set([...Object.keys(expected), ...Object.keys(actual)])

  for (const caseName of [...names].sort()) {
    const e = expected[caseName]
    const a = actual[caseName]

    if (e === undefined) {
      diffs.push({ case: caseName, kind: 'added', detail: 'case exists in run but not in fixture' })
      continue
    }
    if (a === undefined) {
      diffs.push({ case: caseName, kind: 'missing', detail: 'case exists in fixture but not in run' })
      continue
    }

    if (e.outcome !== a.outcome) {
      // The highest-severity diff class: an input that used to be rejected is
      // now accepted, or vice versa.
      diffs.push({
        case: caseName,
        kind: 'outcome',
        detail: `fixture=${e.outcome} run=${a.outcome}`,
        expected: e.outcome === 'throws' ? e.error : e.value,
        actual: a.outcome === 'throws' ? a.error : a.value
      })
      continue
    }

    if (e.outcome === 'throws') {
      const nameChanged = e.error.name !== a.error.name
      const msgChanged = errorMode === 'full' && e.error.message !== a.error.message
      if (nameChanged || msgChanged) {
        diffs.push({
          case: caseName,
          kind: 'error',
          detail: nameChanged ? 'error name changed' : 'error message changed',
          expected: e.error,
          actual: a.error
        })
      }
      continue
    }

    const ev = stringify(e.value)
    const av = stringify(a.value)
    if (ev !== av) {
      diffs.push({ case: caseName, kind: 'value', detail: 'value changed', expected: e.value, actual: a.value })
    }
  }

  return diffs
}

module.exports = {
  loadSuites,
  runSuite,
  compare,
  readFixture,
  writeFixture,
  fixturePath,
  FIXTURES_DIR,
  SUITES_DIR
}
