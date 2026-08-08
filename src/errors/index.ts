'use strict'

import _ = require('../util/_')
import spec = require('./spec')
import type { ErrorSpec, BsvErrorConstructor } from './types'

/**
 * The library's error hierarchy, built at load time from ./spec.
 *
 * Each spec entry becomes a constructor hung off its parent, so nesting in the
 * spec becomes nesting in the namespace:
 *
 *   bsv.errors.Transaction.Input.MissingScript
 *
 * TYPING NOTE: the tree is constructed dynamically, so the child constructors
 * cannot be named in a static type without duplicating the whole spec as a
 * mapped type. The index signature below is deliberate and honest — it says
 * "any name may be present" rather than pretending to a precision this shape
 * cannot deliver. Generating exact per-error types from the spec is worth
 * doing, but it is an API-design decision (it changes what consumers can
 * reference) and belongs with the API pass, not buried in a mechanical
 * conversion.
 *
 * This is also the file whose declaration emit previously failed with TS9005
 * ("declaration emit requires using private name 'NodeError'"); naming the
 * constructor type explicitly is what unblocks it.
 */

function format (message: string, args: ArrayLike<unknown>): string {
  return message
    .replace('{0}', String(args[0]))
    .replace('{1}', String(args[1]))
    .replace('{2}', String(args[2]))
}

const traverseNode = function (parent: BsvErrorConstructor, errorDefinition: ErrorSpec): BsvErrorConstructor {
  const NodeError = function (this: Error, ...args: unknown[]) {
    if (_.isString(errorDefinition.message)) {
      this.message = format(errorDefinition.message, args)
    } else if (_.isFunction(errorDefinition.message)) {
      this.message = String(errorDefinition.message.apply(null, args))
    } else {
      throw new Error('Invalid error definition for ' + errorDefinition.name)
    }
    this.stack = this.message + '\n' + String(new Error().stack)
  } as unknown as BsvErrorConstructor

  NodeError.prototype = Object.create(parent.prototype)
  NodeError.prototype.name = parent.prototype.name + errorDefinition.name
  parent[errorDefinition.name] = NodeError
  if (errorDefinition.errors != null) {
    childDefinitions(NodeError, errorDefinition.errors)
  }
  return NodeError
}

function childDefinitions (parent: BsvErrorConstructor, children: ErrorSpec[]): void {
  _.each(children, function (childDefinition: ErrorSpec) {
    traverseNode(parent, childDefinition)
  })
}

const traverseRoot = function (parent: BsvErrorConstructor, errorsDefinition: ErrorSpec[]): BsvErrorConstructor {
  childDefinitions(parent, errorsDefinition)
  return parent
}

const BsvError = function (this: Error) {
  this.message = 'Internal error'
  this.stack = this.message + '\n' + String(new Error().stack)
} as unknown as BsvErrorConstructor

BsvError.prototype = Object.create(Error.prototype)
BsvError.prototype.name = 'bsv.Error'

traverseRoot(BsvError, spec)

/** Register an additional error subtree (used by ecies/errors and mnemonic/errors). */
function extend (errorSpec: ErrorSpec): BsvErrorConstructor {
  return traverseNode(BsvError, errorSpec)
}

BsvError.extend = extend

export = BsvError
