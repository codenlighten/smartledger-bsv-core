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
}

/** One notice as it was emitted, kept whether or not output was enabled. */
export interface FiredNotice {
  what: string
  since: string | null
  removeIn: string | null
  use: string | null
  message: string
}
