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
