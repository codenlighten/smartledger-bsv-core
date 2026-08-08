/**
 * Declarations for `inherits`, which ships none.
 *
 * Used by the transaction input subclasses and TransactionSignature to set up
 * prototype chains in the pre-class style. Typed loosely on purpose: it mutates
 * the prototype of an existing constructor function, which TypeScript's class
 * model cannot express, and pretending otherwise would be a fiction.
 */
declare module 'inherits' {
  function inherits (ctor: unknown, superCtor: unknown): void
  export = inherits
}
