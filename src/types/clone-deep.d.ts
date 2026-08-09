/**
 * Declarations for clone-deep, which ships none.
 *
 * Used by the interpreter to snapshot stack state for the step callback.
 */
declare module 'clone-deep' {
  function cloneDeep<T> (val: T, instanceClone?: boolean | ((v: unknown) => unknown)): T
  export = cloneDeep
}
