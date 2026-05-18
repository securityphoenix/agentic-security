// IR entry point.
//
// Build per-file IR for every JS/TS file in a project, then build the
// cross-file call graph on top.

import { parseJsFile } from './parser-js.js';
import { buildCallGraph } from './callgraph.js';

export function buildProjectIR(fileContents) {
  const perFile = {};
  for (const [file, code] of Object.entries(fileContents || {})) {
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(file)) continue;
    const ir = parseJsFile(file, code);
    if (ir) perFile[file] = ir;
  }
  const cg = buildCallGraph(perFile);
  return { perFile, callGraph: cg };
}

export { parseJsFile, buildCallGraph };
