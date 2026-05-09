// NEUTRAL: lodash imported but no vulnerable function invoked. Only _.sum is used,
// which isn't in VULN_FUNCTION_HINTS for lodash.
// Expected: supplyChain.functionReachable === 'unknown' (no recorded call sites of vuln fns)
import _ from 'lodash';

export function total(arr) {
  return _.sum(arr);
}
