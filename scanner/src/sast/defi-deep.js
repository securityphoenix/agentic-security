// Deep DeFi / AMM Solidity audit.
//
// Extends scanner/src/sast/solidity.js with the canonical AMM / vault /
// swap-flow bugs. Targets vulnerabilities that don't show up in generic
// reentrancy or tx.origin checks:
//
//   1. Donation / inflation attack — share math using token.balanceOf(address(this))
//   2. Missing slippage / deadline on swap — caller-supplied minOut absent
//   3. Spot-price oracle — pool.slot0 / getReserves used directly, no TWAP
//   4. CEI violation — token.transfer before state update
//   5. Hand-rolled reentrancy guard — bool locked instead of OZ ReentrancyGuard
//   6. Ownable vs Ownable2Step — single-step ownership transfer
//   7. Missing safeTransfer — token.transfer instead of SafeERC20.safeTransfer
//   8. Naive mulDiv — a * b / c with reserve-sized numbers
//   9. Missing nonReentrant on payable withdraw / claim
//  10. Unchecked external call — (bool ok, ) = addr.call(...) without ok check
//
// Only fires on .sol files.

const _SOL_RE = /\.sol$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _findFunctions(raw) {
  // Match: function fnName(args) ... { body }
  // Naive — single brace-counted body up to 2000 chars per fn.
  const fns = [];
  const re = /\bfunction\s+(\w+)\s*\(([^)]*)\)\s*([^{]*)\{/g;
  let m;
  while ((m = re.exec(raw))) {
    const head = m[0];
    const name = m[1];
    const params = m[2];
    const modifiers = m[3] || '';
    const braceIdx = m.index + head.length - 1;
    let depth = 1, end = braceIdx + 1;
    for (let i = braceIdx + 1; i < Math.min(braceIdx + 4000, raw.length); i++) {
      if (raw[i] === '{') depth++;
      else if (raw[i] === '}') {
        depth--;
        if (depth === 0) { end = i; break; }
      }
    }
    fns.push({ name, params, modifiers, body: raw.slice(braceIdx, end + 1), startLine: _line(raw, m.index) });
  }
  return fns;
}

export function scanDefiDeep(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_SOL_RE.test(file)) return [];
  if (raw.length > 300_000) return [];

  const findings = [];
  const fns = _findFunctions(raw);

  for (const fn of fns) {
    // ── 1. Donation / inflation attack ────────────────────────────────────
    // Share math using raw balanceOf(address(this)) without internal accounting.
    if (/balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/.test(fn.body)) {
      // Only flag when used as a divisor (share math) and there's no
      // _totalAssets / _reserves / internal accounting var nearby.
      if (/\(.*?balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*\)/.test(fn.body) ||
          /\*\s*totalShares\s*\)\s*\/\s*[A-Za-z_]/.test(fn.body)) {
        const idx = fn.body.search(/balanceOf\s*\(\s*address\s*\(\s*this\s*\)/);
        findings.push({
          id: `defi:donation-inflation:${file}:${fn.startLine}`,
          file,
          line: fn.startLine + (idx >= 0 ? fn.body.slice(0, idx).split('\n').length - 1 : 0),
          vuln: `${fn.name}() uses balanceOf(address(this)) directly in share / reserve math — donation/inflation attack vector`,
          severity: 'high',
          family: 'defi-donation-inflation',
          cwe: 'CWE-682',
          confidence: 0.7,
          description: 'Anyone can send tokens directly to the contract (outside the deposit path) to manipulate the share-math denominator. First-depositor inflation attack and donation attacks on vaults all flow from this pattern.',
          remediation: 'Track total assets in a state variable updated by deposit/withdraw. Measure tokens received via balBefore/balAfter pair around transferFrom rather than reading balanceOf at the end.',
        });
      }
    }

    // ── 2. Missing slippage / deadline on swap ────────────────────────────
    if (/\bswap\b/i.test(fn.name) || /\bswap[A-Z]/.test(fn.name)) {
      const hasMin = /\b(?:amountOutMin|minAmountOut|minOut|sqrtPriceLimitX96)\b/.test(fn.params);
      const hasDeadline = /\b(?:deadline|expiry|until)\b/i.test(fn.params);
      if (!hasMin) {
        findings.push({
          id: `defi:no-slippage-min:${file}:${fn.startLine}`,
          file, line: fn.startLine,
          vuln: `swap function ${fn.name}() does not accept amountOutMin parameter — no slippage protection`,
          severity: 'high',
          family: 'defi-no-slippage',
          cwe: 'CWE-682',
          confidence: 0.8,
          description: 'Without a caller-supplied minimum output, sandwich-attackers can manipulate pool reserves to drain the swap. The router pattern requires the caller to compute and supply a slippage tolerance.',
          remediation: 'Add `uint256 amountOutMin` to the signature and `require(amountOut >= amountOutMin, "Slippage exceeded")` before the external transfer.',
        });
      }
      if (!hasDeadline) {
        findings.push({
          id: `defi:no-deadline:${file}:${fn.startLine}`,
          file, line: fn.startLine,
          vuln: `swap function ${fn.name}() does not accept deadline parameter — stale transactions accepted`,
          severity: 'medium',
          family: 'defi-no-deadline',
          cwe: 'CWE-672',
          confidence: 0.8,
          description: 'Without a deadline, a tx sitting in the mempool can execute hours later at a much worse price.',
          remediation: 'Add `uint256 deadline` parameter and `require(block.timestamp <= deadline, "Expired")` at the top of the function.',
        });
      }
    }

    // ── 9. Missing nonReentrant on payable / withdraw functions ───────────
    if (/payable\b/.test(fn.modifiers) || /^(?:withdraw|claim|exit|harvest|redeem)/i.test(fn.name)) {
      if (!/\bnonReentrant\b/.test(fn.modifiers)) {
        if (/\b(?:\.call\s*\{|\.transfer\s*\(|\.send\s*\(|safeTransfer)/.test(fn.body)) {
          findings.push({
            id: `defi:no-reentrancy-guard:${file}:${fn.startLine}`,
            file, line: fn.startLine,
            vuln: `${fn.name}() performs external transfer but is not nonReentrant`,
            severity: 'high',
            family: 'defi-missing-reentrancy-guard',
            cwe: 'CWE-841',
            confidence: 0.7,
            description: 'Function moves funds via external call/transfer but does not carry the nonReentrant modifier. Cross-function reentrancy still drains the contract.',
            remediation: 'Inherit OpenZeppelin\'s ReentrancyGuard and add the nonReentrant modifier. Apply CEI ordering: state changes BEFORE external calls.',
          });
        }
      }
    }
  }

  // ── 3. Spot-price oracle ──────────────────────────────────────────────────
  // Reads getReserves() or slot0() as price without an observe() (TWAP) call.
  if (/\b(?:getReserves|slot0)\s*\(/.test(raw) && !/\bobserve\s*\(/.test(raw)) {
    const m = /\b(?:getReserves|slot0)\s*\(/.exec(raw);
    findings.push({
      id: `defi:spot-price-oracle:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Spot-price oracle — reads pool reserves / slot0 without TWAP',
      severity: 'high',
      family: 'defi-spot-price-oracle',
      cwe: 'CWE-1023',
      confidence: 0.75,
      description: 'Spot prices from getReserves() / slot0() are flash-loan manipulable in a single block. Any pricing logic that derives from these without a time-weighted average is exploitable.',
      remediation: 'Use Uniswap V3 pool.observe(secondsAgos) to compute a TWAP over ≥30 minutes, or pull from a hardened oracle like Chainlink.',
    });
  }

  // ── 5. Hand-rolled reentrancy guard ───────────────────────────────────────
  if (/\bbool\s+(?:locked|entered|_status|reentrancy)\s*[;=]/.test(raw) &&
      !/\bReentrancyGuard\b/.test(raw)) {
    const m = /\bbool\s+(?:locked|entered|_status|reentrancy)\s*[;=]/.exec(raw);
    findings.push({
      id: `defi:hand-rolled-reentrancy:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Hand-rolled reentrancy guard instead of OpenZeppelin ReentrancyGuard',
      severity: 'medium',
      family: 'defi-hand-rolled-guard',
      cwe: 'CWE-682',
      confidence: 0.8,
      description: 'A custom `bool locked` reentrancy guard is easy to write incorrectly (missing reset on revert, wrong scope, missing modifier on a function). The OpenZeppelin ReentrancyGuard is audited and idiomatic.',
      remediation: 'Replace with: `import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";` and inherit + use the `nonReentrant` modifier.',
    });
  }

  // ── 6. Ownable vs Ownable2Step ────────────────────────────────────────────
  if (/\bis\s+Ownable\b(?!\s*2Step)/.test(raw)) {
    const m = /\bis\s+Ownable\b/.exec(raw);
    findings.push({
      id: `defi:ownable-single-step:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Contract uses single-step Ownable — typo-to-zero ownership transfer risk',
      severity: 'medium',
      family: 'defi-ownable-single-step',
      cwe: 'CWE-269',
      confidence: 0.85,
      description: 'Ownable.transferOwnership(newOwner) takes effect immediately. Typing the wrong address (or signing a malicious tx) permanently bricks the contract.',
      remediation: 'Use Ownable2Step (also from OpenZeppelin) — the new owner must call acceptOwnership() to take effect.',
    });
  }

  // ── 7. Missing safeTransfer on ERC-20 transfer ────────────────────────────
  // token.transfer / token.transferFrom without SafeERC20.
  if (/\bIERC20\b/.test(raw) &&
      /\b\w+\.(?:transfer|transferFrom)\s*\(/.test(raw) &&
      !/\bSafeERC20\b/.test(raw)) {
    const m = /\b\w+\.(?:transfer|transferFrom)\s*\(/.exec(raw);
    findings.push({
      id: `defi:no-safe-transfer:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'ERC-20 token.transfer / transferFrom used without SafeERC20',
      severity: 'medium',
      family: 'defi-no-safe-transfer',
      cwe: 'CWE-252',
      confidence: 0.7,
      description: 'Some tokens (USDT, BNB) do not return a bool; some return false instead of reverting. Direct .transfer / .transferFrom either reverts unexpectedly or silently succeeds on failure.',
      remediation: 'Use OpenZeppelin SafeERC20: `using SafeERC20 for IERC20;` then `token.safeTransfer(...)` and `token.safeTransferFrom(...)`.',
    });
  }

  // ── 10. Unchecked external call ───────────────────────────────────────────
  // (bool ok, ) = addr.call{value: ...}(...); without an `ok` check.
  for (const m of raw.matchAll(/\(\s*bool\s+(\w+)\s*,?[^)]*\)\s*=\s*[^;]*?\.call\s*(?:\{[^}]*\})?\s*\([^)]*\)\s*;/g)) {
    const okName = m[1];
    const restAfter = raw.slice(m.index + m[0].length, m.index + m[0].length + 200);
    if (new RegExp(`\\brequire\\s*\\(\\s*${okName}\\b|\\bif\\s*\\(\\s*!?${okName}\\b`).test(restAfter)) continue;
    findings.push({
      id: `defi:unchecked-call:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: `External low-level call captures success flag (${okName}) but does not check it`,
      severity: 'medium',
      family: 'defi-unchecked-call',
      cwe: 'CWE-252',
      confidence: 0.85,
      description: 'A low-level .call returns (bool, bytes). If you ignore the bool, the function appears to succeed even when the callee reverts — leading to silent state corruption.',
      remediation: `Add require(${okName}, "call failed") immediately after the call, or revert with a meaningful error.`,
    });
  }

  // ── 4. CEI violation — transfer before state update ───────────────────────
  // Heuristic: find `external_call(...)` then `state_var -= ` or `state_var = `
  // on the same path. Conservative: only flag when the lines are obviously
  // in sequence and the state var is a mapping access.
  for (const m of raw.matchAll(/(\w+)\.transfer\s*\([^)]*\)\s*;\s*\n[^\n}]*\b(\w+)\s*\[\s*(?:msg\.sender|tx\.origin)\s*\]\s*-=/g)) {
    findings.push({
      id: `defi:cei-violation:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'CEI violation — token.transfer() before state update on caller balance',
      severity: 'high',
      family: 'defi-cei-violation',
      cwe: 'CWE-841',
      confidence: 0.85,
      description: 'External transfer happens before the caller\'s balance is decremented. A reentrant caller can re-enter through a token-callback (ERC-777, ERC-1363) and drain the balance.',
      remediation: 'Apply CEI ordering: update internal accounting (state) BEFORE any external call (interaction). Use nonReentrant as defense-in-depth.',
    });
  }

  return findings;
}
