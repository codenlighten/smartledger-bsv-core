'use strict'

import Random from '../crypto/random'

/**
 * The small lodash-shaped helper set the library grew instead of taking a
 * dependency. Predicates are typed as type guards so callers narrow correctly
 * rather than needing casts after an `isString`/`isNumber` check.
 */
const _ = {
  isArray: (t: unknown): t is unknown[] => Array.isArray(t),
  isNumber: (t: unknown): t is number => typeof t === 'number',
  // Mirrors the original's truthiness check, so `null` is excluded but the
  // guard deliberately does not claim non-nullness beyond that.
  isObject: (t: unknown): t is object => Boolean(t) && typeof t === 'object',
  isString: (t: unknown): t is string => typeof t === 'string',
  isUndefined: (t: unknown): t is undefined => typeof t === 'undefined',
  isFunction: (t: unknown): t is (...args: unknown[]) => unknown => typeof t === 'function',
  isNull: (t: unknown): t is null => t === null,
  isDate: (t: unknown): t is Date => t instanceof Date,

  extend: <A extends object, B>(a: A, b: B): A & B => Object.assign(a, b),
  noop: (): void => { },

  every: <T>(a: T[], f?: (t: T, i: number, all: T[]) => unknown): boolean =>
    a.every(f ?? ((t: T) => Boolean(t))),
  map: <T, R = T>(a: Iterable<T>, f?: (t: T, i: number) => R): R[] =>
    Array.from(a).map(f ?? ((t: T) => t as unknown as R)),
  includes: <T>(a: T[], e: T): boolean => a.includes(e),
  each: <T>(a: T[], f: (t: T, i: number, all: T[]) => void): void => { a.forEach(f) },
  clone: <T extends object>(o: T): T => Object.assign({}, o),

  pick: <T extends object, K extends keyof T>(object: T, keys: K[]): Partial<Pick<T, K>> => {
    const obj: Partial<Pick<T, K>> = {}
    keys.forEach(key => {
      if (typeof object[key] !== 'undefined') { obj[key] = object[key] }
    })
    return obj
  },

  values: <T extends object>(o: T): Array<T[keyof T]> => Object.values(o),
  filter: <T>(a: T[], f: (t: T, i: number, all: T[]) => unknown): T[] => a.filter(t => Boolean(f(t, a.indexOf(t), a))),
  reduce: <T, A>(a: T[], f: (acc: A, t: T, i: number, all: T[]) => A, s: A): A => a.reduce(f, s),
  without: <T>(a: T[], n: T): T[] => a.filter(t => t !== n),

  /**
   * CSPRNG-backed Fisher-Yates.
   *
   * Output-order shuffling is a privacy primitive (Transaction.shuffleOutputs);
   * a predictable PRNG defeats the purpose, which is why this does not use
   * Math.random().
   */
  shuffle: <T>(a: T[]): T[] => {
    const result = a.slice(0)
    for (let i = result.length - 1; i > 0; i--) {
      const buf = Random.getRandomBuffer(4)
      const r = buf.readUInt32BE(0) / 0x100000000
      const j = Math.floor(r * (i + 1))
      // Both indices are within [0, length) by construction; the assertions
      // satisfy noUncheckedIndexedAccess without loosening it globally.
      const ti = result[i] as T
      const tj = result[j] as T
      result[i] = tj
      result[j] = ti
    }
    return result
  },

  difference: <T>(a: T[], b: T[]): T[] => a.filter(t => !b.includes(t)),
  findIndex: <T>(a: T[], f: (t: T, i: number, all: T[]) => unknown): number =>
    a.findIndex((t, i, all) => Boolean(f(t, i, all))),
  some: <T>(a: T[], f: (t: T, i: number, all: T[]) => unknown): boolean =>
    a.some((t, i, all) => Boolean(f(t, i, all))),
  range: (n: number): number[] => [...Array(n).keys()]
}

export = _
