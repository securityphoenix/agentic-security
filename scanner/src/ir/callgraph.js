// Cross-file call graph from the JS/TS IR.
//
// Resolves call sites to callee function IDs. Resolution rules (best-effort):
//   1. Direct function call to a name defined in the same file → resolve to that fn.
//   2. Method call `obj.foo()` where obj is a class instance with a known
//      method `foo` in the same file → resolve to that method.
//   3. Module-imported name: look up in another file's exports.
//   4. Anything else → unresolved; the dataflow engine treats the callee as
//      an opaque sink for taint.

export function buildCallGraph(perFileIR) {
  // perFileIR is { [file]: parseJsFile output }
  const functions = new Map(); // qid → FunctionIR
  const byNameInFile = new Map(); // file → Map<name, qid>
  const classMethods = new Map(); // 'ClassName.method' → qid

  for (const file of Object.keys(perFileIR || {})) {
    const ir = perFileIR[file];
    if (!ir || !ir.functions) continue;
    byNameInFile.set(file, new Map());
    for (const fn of ir.functions) {
      functions.set(fn.qid, fn);
      byNameInFile.get(file).set(fn.name, fn.qid);
      // Class methods: qid carries the class name as the scope.
      const m = fn.qid.match(/::([A-Z]\w*)::(\w+)@/);
      if (m) classMethods.set(`${m[1]}.${m[2]}`, fn.qid);
    }
  }

  // Resolve each call site.
  const edges = []; // { caller, site, callee, ambiguous? }
  for (const fn of functions.values()) {
    for (const c of (fn.calls || [])) {
      if (!c.callee) { edges.push({ caller: fn.qid, site: c.site, callee: null, line: c.line }); continue; }
      // 1. Direct name in same file
      const sameFileMap = byNameInFile.get(fn.file);
      const resolved = sameFileMap?.get(c.callee) ||
                       classMethods.get(c.callee) ||
                       // 2. ClassName.method form
                       (c.callee.includes('.') ? classMethods.get(c.callee) : null) ||
                       null;
      edges.push({ caller: fn.qid, site: c.site, callee: resolved, calleeName: c.callee, line: c.line });
    }
  }

  // Reverse index: callee → callers.
  const callersOf = new Map();
  for (const e of edges) {
    if (!e.callee) continue;
    if (!callersOf.has(e.callee)) callersOf.set(e.callee, []);
    callersOf.get(e.callee).push(e);
  }
  return { functions, edges, callersOf };
}
