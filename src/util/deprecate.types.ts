/**
 * Types for util/deprecate. Separate from the implementation because that module uses
 * `export =` for CommonJS interop, which TypeScript will not combine with named exports.
 */

/** Everything a notice can say. `what` is the only field with no sensible default. */
export interface DeprecationOptions {
  /** the API being deprecated, as a caller writes it; the dedup key */
  what: string
  /** version that deprecated it */
  since?: string
  /** version that will remove it (a major) */
  removeIn?: string
  /** the replacement, as a caller would write it */
  use?: string
  /** one clause; why it is wrong, not what to do */
  why?: string
  /**
   * Stable id pairing this commitment to its row in `docs/RELEASE-2.0.0.md`.
   * Never printed and never part of the dedup key: it exists so the plan and the code can be
   * checked against each other by something other than prose. Required on any registration
   * carrying `removeIn: '2.0.0'`, which `test/properties/release_2_plan.js` enforces.
   */
  plan?: string
}

/** One notice as it was emitted, kept whether or not output was enabled. */
export interface FiredNotice {
  what: string
  since: string | null
  removeIn: string | null
  /** The stable id of the planned break, as docs/RELEASE-2.0.0.md lists it. */
  plan: string | null
  use: string | null
  message: string
}
