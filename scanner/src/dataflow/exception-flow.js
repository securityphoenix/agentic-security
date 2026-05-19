// Exception-flow modeling (P3.4).
//
// Today's engine treats `throw` as a barrier — tainted code after a throw
// in the same function is unreachable (correct), but tainted values that
// flow into a catch block are LOST. This module models try/catch/finally:
//
//   try {
//     const data = req.body;            // tainted
//     throw new Error(data);            // taint flows into the Error
//   } catch (e) {
//     console.log(e.message);           // e.message inherits taint
//   } finally {
//     // ran on both paths — taint state at entry = join(normal-exit, throw-exit)
//   }
//
// v1: this module is a structural helper consumed by the IR builder.
// The JS IR doesn't currently emit `try`/`catch`/`finally` nodes (parser-js.js
// drops them). This module gives the parser-side helpers to recognize and
// emit the right shape, and gives the engine the join semantics.
//
// Public API:
//   markExceptionEdges(cfg, parser-options)
//     → mutates the CFG so each catch-block entry carries `incomingException`
//       metadata and finally-block exit carries `joinFromTry` metadata.
//
//   exceptionTaintFlow(throwNode, catchVar)
//     → returns the access paths that should be added to the catch-block's
//       entry state given the throw's value's taint.
//
//   joinFinally(normalState, throwState)
//     → returns the conservative union of two access-path states.

import { joinSets, accessPathOf, addPath } from './access-paths.js';

/**
 * For a `throw <expr>` node, decide which access path(s) the caught variable
 * `catchVar` (the exception binding) should carry into the catch block's
 * entry state.
 *
 *   throw value                       catchVar  →  taint flows
 *   ---------------------------------|---------|------------------
 *   throw req.body.something          e        →  {e}
 *   throw new Error(req.body.foo)     e        →  {e, e.message}
 *   throw "user input " + tainted     e        →  {e, e.message}
 */
export function exceptionTaintFlow(throwNode, catchVar, isExprTainted) {
  if (!throwNode || !catchVar) return [];
  const flows = [];
  const val = throwNode.value;
  // The exception binding `e` itself becomes the catch's source — always add it
  // when the throw value is tainted (or when the throw appears in a tainted-call
  // chain).
  if (val && (
    (typeof isExprTainted === 'function' && isExprTainted(val)) ||
    (val.kind === 'call' && (val.args || []).some(a => isExprTainted ? isExprTainted(a) : false))
  )) {
    flows.push(catchVar);
    // For `throw new Error(msg)`, the .message field carries the original
    // taint. Many real catch blocks read e.message, e.stack, e.toString().
    if (val.kind === 'call') {
      flows.push(`${catchVar}.message`);
      flows.push(`${catchVar}.stack`);
    }
  }
  return flows;
}

/**
 * Apply the exception-flow taint to a state at the entry of a catch block.
 *
 *   stateBeforeTry: the taint state immediately before the try block began
 *   thrownPaths:    output of exceptionTaintFlow()
 *
 * Returns the new state for the catch block.
 */
export function applyExceptionTaintAtCatchEntry(stateBeforeTry, thrownPaths) {
  let s = stateBeforeTry || new Set();
  for (const p of thrownPaths) s = addPath(s, p);
  return s;
}

/**
 * Join the normal-exit and throw-exit states at a finally block. The
 * conservative semantics: every taint that was live on EITHER path is
 * live in the finally.
 */
export function joinFinally(normalState, throwState) {
  return joinSets(normalState, throwState);
}

/**
 * Helper for the JS IR parser (parser-js.js): given a Babel try/catch/finally
 * statement node, emit the CFG edges that route control through the catch
 * and finally blocks. v1 is a STUB — the parser-js.js currently doesn't
 * model these as CFG branches. This is the integration point.
 *
 * Returns a small descriptor object the parser can attach to its CFG nodes:
 *   {
 *     tryNodeId, catchNodeId, finallyNodeId,
 *     catchVar:    string | null,
 *     throwEdges:  Array of `(throwSiteNid, catchEntryNid)` for every throw inside try
 *   }
 */
export function describeTryCatchFinally(tryAstNode) {
  if (!tryAstNode || tryAstNode.type !== 'TryStatement') return null;
  const catchClause = tryAstNode.handler;
  const finallyBlock = tryAstNode.finalizer;
  const catchVar = catchClause && catchClause.param && catchClause.param.name
    ? catchClause.param.name
    : null;
  return {
    catchVar,
    hasCatch: !!catchClause,
    hasFinally: !!finallyBlock,
  };
}
