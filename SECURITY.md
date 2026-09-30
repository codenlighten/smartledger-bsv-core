# Security

## Reporting a vulnerability

Email **security@smartledger.technology**. Please do not open a public issue for a
vulnerability that affects funds or consensus.

Include what you have: the version, the flags passed to `verify()`, and a script or transaction
that reproduces it. A failing case is worth more than a description, and a raw hex transaction
plus the flag word is usually enough.

## What counts as a security issue here

This package decides whether a spend is valid, so the severity of a bug follows its direction:

- **Accepting a script the network rejects** is the serious direction. Software that trusts this
  package would treat an unspendable transaction as settled. Report it as a vulnerability.
- **Rejecting a script the network accepts** fails closed. It is a bug, and can be a denial of
  service for whoever depends on it, but it does not create a false belief that value moved.
- **Failing for a reason the node does not give** is a correctness bug worth reporting: the
  history of this package is that a wrong reason has repeatedly been the visible symptom of a
  wrong rule.

Signature and digest handling, era and flag selection, and the script interpreter are the parts
where a defect is most likely to be exploitable.

## What is verified, and what that does not cover

Every release replays the reference node's own vectors — `bitcoin-sv` v1.2.2's
`script_tests.json` (1483 rows) and `sighash.json` (1000 rows) — and CI fails on a single
disagreement. See **Verification** in the README.

Those fixtures are not exhaustive. Two known gaps, documented because they have already cost
real bugs: every row carries transaction version 1, and no row pairs `LOW_S` with a hash-type
expectation. Consensus paths outside the fixtures are covered by this package's own tests, which
are weaker evidence than the node's data.

This package has not had an external security audit.

## Supported versions

The latest 1.x release receives fixes. Consensus fixes are not backported to earlier 1.x
versions; upgrade instead. See **Stability** in the README for how a network activation is
versioned.
