/**
 * Shape of the declarative error definitions in ./spec.
 *
 * Lives in its own module because ./spec uses `export =` to keep its
 * `require()` shape (a bare array), and TypeScript forbids an export
 * assignment alongside other exported members.
 */
export interface ErrorSpec {
  /** Constructor name, e.g. 'InvalidB58Char'. */
  name: string
  /**
   * Either a template whose {0}/{1}/{2} placeholders are filled positionally
   * from the constructor arguments, or a function receiving those arguments.
   */
  message: string | ((...args: unknown[]) => string)
  /** Nested definitions, namespaced under this one. */
  errors?: ErrorSpec[]
}

/**
 * A constructor produced from an ErrorSpec entry.
 *
 * The tree is built dynamically at load time, so child constructors cannot be
 * named statically without duplicating the whole spec as a mapped type. The
 * index signature is deliberate and honest: it says "any name may be present"
 * rather than claiming a precision this shape cannot deliver. Generating exact
 * per-error types is worth doing, but it changes what consumers can reference
 * and so belongs with the API pass.
 */
export interface BsvErrorConstructor {
  new (...args: unknown[]): Error
  prototype: Error
  /** Register an additional error subtree (used by ecies/errors, mnemonic/errors). */
  extend: (spec: ErrorSpec) => BsvErrorConstructor
  /** Dynamically attached child errors. */
  [child: string]: unknown
}
