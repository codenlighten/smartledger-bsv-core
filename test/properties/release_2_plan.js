'use strict'
/**
 * docs/RELEASE-2.0.0.md must list every breaking change this package has promised.
 *
 * The commitments live in three source files, and until that document existed they were recorded
 * nowhere else. A plan maintained by hand drifts from the code, and a major assembled from
 * whatever happens to be in the tree is how the sibling package came to ship six majors in 82
 * days. So the pairing is enforced in both directions.
 *
 * The key is the `plan:` id each registration carries, mirrored in the plan's first column.
 * Neither obvious alternative works, and the sibling package measured why: keying on the `since`
 * version alone accepted any new commitment whose version an existing row already mentioned —
 * including the ordinary case of a deprecation added in the version being shipped — and keying on
 * the registering file would reject two deprecations landing in one file in one release while
 * treating a file move as a different commitment. With the id as identity, `since` and the file
 * are checked as FIELDS of the matched row, so a commitment whose version or location moved
 * without the plan being updated is caught.
 *
 * This reads `src/`, not `dist/`: the registration is a property of the source, and a stale build
 * must not be able to answer the question.
 */
var should = require('chai').should()
var fs = require('fs')
var path = require('path')

var ROOT = path.join(__dirname, '..', '..')
var PLAN = path.join(ROOT, 'docs', 'RELEASE-2.0.0.md')

function tsFiles (dir, acc) {
  fs.readdirSync(dir, { withFileTypes: true }).forEach(function (e) {
    var p = path.join(dir, e.name)
    if (e.isDirectory()) tsFiles(p, acc)
    else if (e.name.slice(-3) === '.ts' && e.name.slice(-9) !== '.types.ts') acc.push(p)
  })
  return acc
}

// Every registered 2.0.0 deprecation in src/, excluding the deprecate module itself — its
// occurrences document the mechanism rather than promising anything.
function registered () {
  var found = []
  tsFiles(path.join(ROOT, 'src'), []).forEach(function (f) {
    if (f.indexOf(path.join('util', 'deprecate.ts')) !== -1) return
    var lines = fs.readFileSync(f, 'utf8').split('\n')
    lines.forEach(function (ln, i) {
      if (!/removeIn:\s*'2\.0\.0'/.test(ln)) return
      var blk = lines.slice(Math.max(0, i - 22), Math.min(lines.length, i + 22)).join('\n')
      var since = blk.match(/since:\s*'([^']+)'/)
      var id = blk.match(/plan:\s*'([^']+)'/)
      found.push({
        file: path.relative(ROOT, f).split(path.sep).join('/'),
        since: since ? since[1] : null,
        id: id ? id[1] : null,
        line: i + 1
      })
    })
  })
  return found
}

// | id | since | what | instead | registered in |
function planRows (plan) {
  return plan.split('\n').filter(function (l) {
    return /^\|\s*`[a-z0-9-]+`\s*\|\s*\d+\.\d/.test(l)
  }).map(function (l) {
    var c = l.split('|').map(function (x) { return x.trim() })
    return { id: c[1].replace(/`/g, ''), since: c[2], file: (c[5] || '').replace(/`/g, '') }
  })
}

describe('the 2.0.0 plan', function () {
  var plan = fs.readFileSync(PLAN, 'utf8')
  var items = registered()
  var rows = planRows(plan)

  it('finds the registered commitments at all (the instrument must not be empty)', function () {
    // An enumeration that silently finds nothing would make every assertion below vacuous.
    items.length.should.be.above(2, 'the deprecation scan found almost nothing — check the scan')
  })

  it('parses the plan table back out (the second instrument must not be empty either)', function () {
    rows.length.should.be.above(2, 'no table rows parsed — check the table shape')
    rows.forEach(function (r) {
      r.file.should.match(/^src\//,
        'row ' + r.id + ' has no `registered in` path: got ' + JSON.stringify(r.file))
    })
  })

  it('every registered 2.0.0 deprecation declares a `since` and a unique plan id', function () {
    var seen = {}
    items.forEach(function (it_) {
      should.exist(it_.since, it_.file + ':' + it_.line + ' registers 2.0.0 without a since')
      should.exist(it_.id,
        it_.file + ':' + it_.line + ' registers removeIn 2.0.0 with no plan: id')
      should.not.exist(seen[it_.id],
        'two registrations share the plan id ' + it_.id + ' (' + it_.file + ':' + it_.line + ')')
      seen[it_.id] = it_
    })
  })

  it('every registered 2.0.0 deprecation appears in the plan, matched by id', function () {
    var have = {}
    rows.forEach(function (r) { have[r.id] = r })
    var absent = items.filter(function (it_) { return !have[it_.id] })
    absent.should.have.length(0,
      'these register removeIn 2.0.0 but no plan row carries their id: ' +
      absent.map(function (a) { return a.file + ':' + a.line + ' (' + a.id + ')' }).join(', '))
  })

  it('every plan row is backed by a live registration — a row cannot be left behind', function () {
    var have = {}
    items.forEach(function (it_) { have[it_.id] = it_ })
    var unbacked = rows.filter(function (r) { return !have[r.id] })
    unbacked.should.have.length(0,
      'these plan rows promise a 2.0.0 change that nothing in src/ registers: ' +
      unbacked.map(function (r) { return r.id }).join(', '))
  })

  it('agrees with the plan on each matched commitment\'s version and location', function () {
    var byId = {}
    items.forEach(function (it_) { byId[it_.id] = it_ })
    rows.forEach(function (r) {
      var reg = byId[r.id]
      if (!reg) return // the reverse test above owns that failure
      r.since.should.equal(reg.since,
        r.id + ': the plan says since ' + r.since + ', the code registers ' + reg.since)
      r.file.should.equal(reg.file,
        r.id + ': the plan says it is registered in ' + r.file + ', it is in ' + reg.file)
    })
  })

  it('every `since` names a version that actually shipped', function () {
    var changelog = fs.readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8')
    items.forEach(function (it_) {
      changelog.should.match(
        new RegExp('^## \\[?' + it_.since.replace(/\./g, '\\.') + '\\]?', 'm'),
        it_.id + ' claims since ' + it_.since + ', which has no CHANGELOG entry')
    })
  })

  it('states that it does not schedule the major, and what it excludes', function () {
    plan.should.match(/No date is set/)
    plan.should.match(/Consensus tracking/)
    plan.should.match(/api-surface\.json/)
  })

  it('is linked from the README so it is discoverable', function () {
    var readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8')
    readme.should.match(/RELEASE-2\.0\.0\.md/)
  })

  it('shares its ids with @smartledger/bsv so the two plans stay comparable', function () {
    // All three commitments are ports. If an id here drifts from the sibling's, the comparison
    // the plan promises silently stops working.
    plan.should.match(/the same strings `@smartledger\/bsv` uses/)
    ;['script-fromhex-not-whole-hex', 'output-script-mutated-in-place',
      'message-verify-high-s-accept'].forEach(function (id) {
      plan.indexOf('`' + id + '`').should.be.above(-1, 'the plan no longer carries the id ' + id)
    })
  })
})
