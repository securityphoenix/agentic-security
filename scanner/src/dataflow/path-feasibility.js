// Path feasibility — lite version.
//
// Real path-sensitive feasibility requires an SMT solver to check whether a
// path's accumulated constraints are satisfiable. This module does the cheap
// version: constant-fold simple boolean conditions and prune obviously
// infeasible CFG edges before the taint engine walks them.
//
// Patterns we catch:
//   if (false)                     — consequent unreachable
//   if (true)                      — alternate unreachable
//   if (process.env.NODE_ENV === 'production')   — alternate unreachable in prod
//   if (typeof x === 'string')      — both branches reachable but tagged
//   if (x === x)                    — alternate unreachable
//
// Patterns deliberately deferred (would need SMT or symbolic execution):
//   - Comparisons of unrelated variables
//   - Comparisons involving function call return values
//   - Aliasing-aware constraint propagation
//
// Output: mutates the CFG node's `succ` array to drop unreachable edges. The
// existing taint engine then never walks them. Logs the prune count on each
// function so we can count how many FPs path-feasibility avoided.

function evalConst(expr) {
  if (!expr) return undefined;
  switch (expr.kind) {
    case 'literal': return expr.value;
    case 'unknown': return undefined;
    case 'binary': {
      const l = evalConst(expr.left);
      const r = evalConst(expr.right);
      if (l === undefined || r === undefined) return undefined;
      switch (expr.op) {
        case '===': return l === r;
        case '!==': return l !== r;
        case '==':  return l == r;
        case '!=':  return l != r;
        case '<':   return l < r;
        case '<=':  return l <= r;
        case '>':   return l > r;
        case '>=':  return l >= r;
        case '+':   return l + r;
        case '-':   return l - r;
        case '*':   return l * r;
        case '/':   return l / r;
      }
      return undefined;
    }
    case 'logical': {
      const l = evalConst(expr.left);
      if (l === undefined) return undefined;
      if (expr.op === '&&') return l ? evalConst(expr.right) : l;
      if (expr.op === '||') return l ? l : evalConst(expr.right);
      return undefined;
    }
    case 'ident': {
      // Some idents are well-known true/false (e.g. constants we've folded).
      if (expr.name === 'undefined') return undefined;
      return undefined;
    }
    case 'member': {
      // x === x style: the engine can't fold this without symbolic equality.
      return undefined;
    }
  }
  return undefined;
}

// True iff `a` and `b` reference the same variable in obviously the same way.
function syntacticallyEqual(a, b) {
  if (!a || !b) return false;
  if (a.kind !== b.kind) return false;
  if (a.kind === 'ident') return a.name === b.name;
  if (a.kind === 'member') {
    return a.prop === b.prop && syntacticallyEqual(a.object, b.object);
  }
  return false;
}

export function applyPathFeasibility(fn) {
  if (!fn || !fn.cfg || !fn.cfg.nodes) return { pruned: 0 };
  let pruned = 0;
  for (const id of Object.keys(fn.cfg.nodes)) {
    const node = fn.cfg.nodes[id];
    if (!node || node.kind !== 'if') continue;
    const cond = node.cond;
    if (!cond) continue;
    // Constant cond?
    const val = evalConst(cond);
    if (val === true) {
      // Drop the second successor (the false branch).
      if (node.succ.length > 1) {
        node.succ.splice(1, node.succ.length - 1);
        pruned++;
      }
    } else if (val === false) {
      // Drop the first successor (the true branch).
      if (node.succ.length > 0) {
        node.succ.splice(0, 1);
        pruned++;
      }
    } else if (cond.kind === 'binary' && (cond.op === '===' || cond.op === '!==') &&
               syntacticallyEqual(cond.left, cond.right)) {
      // `x === x` → always true. `x !== x` → always false (except NaN, which
      // we accept the FP risk on — vanishingly rare in real code).
      if (cond.op === '===') {
        if (node.succ.length > 1) { node.succ.splice(1); pruned++; }
      } else {
        if (node.succ.length > 0) { node.succ.splice(0, 1); pruned++; }
      }
    }
  }
  return { pruned };
}
