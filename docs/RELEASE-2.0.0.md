# 2.0.0 — the planned major

**No date is set, and nothing here ships early.** This file does not schedule the major; it
records what the major is already committed to, so that when one is planned it is assembled from
a list rather than from whatever happens to be in the tree that day. The sibling package
`@smartledger/bsv` published six majors in 82 days before writing its commitments down
(`STABILITY.md` there), and that is the outcome this file exists to avoid here.

Three breaking changes are promised in code today, each by a `deprecate()` call carrying
`removeIn: '2.0.0'`. Until this file existed they were recorded nowhere else: the promise was in
consumers' logs and in three source files, and no list of it existed to plan from.

`test/properties/release_2_plan.js` asserts that **every `removeIn: '2.0.0'` registered in `src/`
appears below, and that every row below is backed by a live registration**. The pairing is keyed
on the **`id`** in the first column, which each registration carries as a `plan:` field. `since`
cannot be the key, because versions repeat across rows. Nor can the registering file: two APIs in
one file may legitimately be deprecated in the same release, and a file move is not a change of
promise. So `since` and the registering file are checked as **fields of the matched row** instead.

The ids are deliberately **the same strings `@smartledger/bsv` uses** for the same commitments, so
the two packages' plans can be compared directly. All five of these are ported changes, and the
port is the point: a commitment honoured in one package and forgotten in the other is how the two
drift.

| id | since | what stops working | what to write instead | registered in |
|---|---|---|---|---|
| `script-fromhex-not-whole-hex` | 1.1.0 | `Script.fromHex()` on a string that is **not whole hex** | round-trip first: `Script.fromHex(h).toHex() === h.toLowerCase()` | `src/script/script.ts` |
| `output-script-mutated-in-place` | 1.7.0 | **mutating a parsed output script in place** and expecting it to serialize | `output.setScript(output.script)` after mutating, or build the script before setting it | `src/transaction/output.ts` |
| `message-verify-high-s-accept` | 1.8.0 | `Message#verify()` **accepting a non-canonical (high-s) signature** | `verify(address, sig, { lowS: true })` | `src/message/message.ts` |
| `mnemonic-fromstring-generates` | 1.10.0 | `Mnemonic.fromString()` with **anything but a non-empty string** — it generates a fresh phrase instead of refusing, and `[]` and a Buffer give keys anyone can derive | `Mnemonic.isValid(phrase)` before parsing, `Mnemonic.fromSeed(buffer)` for a seed, `Mnemonic.fromRandom()` for a new phrase | `src/mnemonic/mnemonic.ts` |
| `hdprivatekey-fromstring-empty` | 1.10.0 | `HDPrivateKey.fromString('')` — the type check passes an empty string and the constructor reads one as no argument, so it generates | a non-empty xprv you have checked, or `HDPrivateKey.fromRandom()` | `src/hdprivatekey.ts` |

`src/util/deprecate.ts` warns once per API per process and **never throws**, because a deprecation
that throws is a breaking change wearing a warning's name. The `plan:` id is never printed: it is
not part of the notice and not part of the dedup key.

## What is NOT promised here

This file covers registered deprecations only. Two things are deliberately outside it:

- **Consensus tracking**, which the README's stability section puts ahead of API stability: a
  network activation that changes what this package accepts ships in a **minor**, and that is not
  a 2.0.0 matter.
- **The 1.x API surface**, which is pinned by name and type in
  [`test/fixtures/api-surface.json`](../test/fixtures/api-surface.json) and enforced by
  `npm run check:api`. A 2.0.0 may remove names from it; nothing in 1.x may.

## What "solid" means for this release

1. **No item lands without a notice already in consumers' logs.** Each row's `since` names the
   version whose logs first carried it, and the test requires that version to have a `CHANGELOG`
   entry — "the notice has been there since 1.1.0" is only true if 1.1.0 shipped.
2. **Nothing may be added to 2.0.0 that has not shipped a warning in a minor first.** That is the
   whole point of the mechanism, and it is why this file is test-enforced rather than
   hand-maintained.
3. **Every row stays comparable to `@smartledger/bsv`'s plan.** Where a commitment exists in both,
   the id is shared, so a change honoured in one package and dropped in the other is visible.
