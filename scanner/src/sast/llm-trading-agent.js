// LLM autonomous-trading-agent security audit.
//
// Targets code that gives an LLM agent on-chain transaction authority. These
// patterns aren't generic LLM prompt-injection issues — they're financial-
// loss-shaped, so a missed check means real money.
//
// Coverage:
//   1. send_raw_transaction / signTransaction / sendTransaction without a
//      prior eth_call simulation.
//   2. Trading agent code with no MAX_SINGLE_TX or MAX_DAILY_SPEND constant
//      (when an LLM-call API is present in the same file).
//   3. RPC response / token name / pair label concatenated into an LLM
//      prompt without sanitization (prompt-injection-via-onchain-data).
//   4. Autonomous trading loop without a circuit breaker
//      (consecutive-loss counter or hourly-loss-pct halt).
//   5. Raw hex private key in source: PRIVATE_KEY = "0x..."
//
// Fires on .py / .js / .ts / .mjs / .cjs files. The agent ↔ wallet pattern
// usually lives in Python or JS today; we cover both.

const _SUPPORTED_EXT = /\.(?:py|js|jsx|ts|tsx|mjs|cjs)$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _looksLikeTradingAgent(raw) {
  // Heuristic: file imports web3 / ethers / viem / solana AND mentions an LLM
  // SDK (anthropic / openai / langchain / together / groq) OR an agent loop.
  const onchain = /\b(?:from\s+web3\b|import\s+\{?[^}]*\}?\s+from\s+['"]ethers|import\s+\{?[^}]*\}?\s+from\s+['"]viem|from\s+solders|from\s+anchorpy)\b/.test(raw);
  const llmSdk = /\b(?:anthropic|openai|langchain|together|groq|@anthropic-ai|@openai)\b/i.test(raw);
  const agentLoop = /\b(?:while\s+True|while\s*\(\s*true|asyncio\.run|setInterval|setTimeout.*?ms\s*\)|trading_loop|run_agent)\b/i.test(raw);
  return onchain && (llmSdk || agentLoop);
}

const _SIGN_OR_SEND_RE = /\b(?:send_raw_transaction|sendRawTransaction|signTransaction|sign_transaction|sendTransaction)\s*\(/;
const _ETH_CALL_RE = /\b(?:eth_call|eth\.call|w3\.eth\.call|client\.call|estimateGas|estimate_gas|simulate(?:_transaction)?|callStatic)\b/;
const _SPEND_LIMIT_RE = /\b(?:MAX_SINGLE_TX|MAX_DAILY_SPEND|MAX_TX_VALUE|DAILY_LIMIT|SPEND_LIMIT|TX_BUDGET|TRADE_BUDGET)\b/;
const _CIRCUIT_BREAKER_RE = /\b(?:circuit_breaker|CircuitBreaker|consecutive_losses|max_hourly_loss|HOURLY_LOSS|MAX_DRAWDOWN|halt(?:_trading|_loop)?)\b/i;

const _PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(?:previous|all)\s+instructions/i,
  /system\s+prompt/i,
  /transfer\s+.{0,50}\s+to\b/i,
  /approve\s+.{0,50}\s+for\b/i,
  /\bsend\s+.{0,50}\s+to\s+0x[0-9a-fA-F]{40}\b/i,
];

const _ONCHAIN_DATA_SOURCES = [
  'token_name', 'pair_name', 'pair_label', 'token_symbol', 'tokenName',
  'pairName', 'pairLabel', 'tokenSymbol', 'pool_name', 'event_log',
  'metadata', 'rpc_response', 'event_data',
];

const _PROMPT_SINKS = /\b(?:client\.messages\.create|chat\.completions\.create|generate|invoke|stream|completion)\s*\(/;

export function scanLlmTradingAgent(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_SUPPORTED_EXT.test(file)) return [];
  if (raw.length > 200_000) return [];
  if (!_looksLikeTradingAgent(raw)) return [];

  const findings = [];

  // 1. send_raw_transaction without prior eth_call simulation.
  for (const m of raw.matchAll(new RegExp(_SIGN_OR_SEND_RE.source, 'g'))) {
    // Look ±50 lines for any simulation call.
    const lineNum = _line(raw, m.index);
    const lines = raw.split('\n');
    const window = lines.slice(Math.max(0, lineNum - 50), lineNum + 5).join('\n');
    if (_ETH_CALL_RE.test(window)) continue;
    findings.push({
      id: `llm-trading:no-simulation:${file}:${lineNum}`,
      file, line: lineNum,
      vuln: 'Trading agent sends transaction without prior simulation (eth_call / estimateGas)',
      severity: 'high',
      family: 'llm-trading-no-simulation',
      cwe: 'CWE-754',
      confidence: 0.7,
      description: 'The agent signs and sends a transaction without first calling eth_call / estimateGas / callStatic to simulate the outcome. A bug, prompt-injection, or oracle manipulation that produces a bad tx silently lands on-chain — and reverts there cost gas.',
      remediation: 'Add a pre-send simulation: const result = await w3.eth.call(tx); decode the expected output; require it matches an expected_min_out before signTransaction + sendRawTransaction.',
    });
  }

  // 2. No spend-limit constant
  if (!_SPEND_LIMIT_RE.test(raw)) {
    // Only flag when the file actually signs / sends.
    if (_SIGN_OR_SEND_RE.test(raw)) {
      const m = _SIGN_OR_SEND_RE.exec(raw);
      findings.push({
        id: `llm-trading:no-spend-limit:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'LLM trading agent has no per-tx / daily spend limit constant',
        severity: 'critical',
        family: 'llm-trading-no-spend-limit',
        cwe: 'CWE-770',
        confidence: 0.7,
        description: 'Code can sign and send transactions but no MAX_SINGLE_TX / MAX_DAILY_SPEND / TX_BUDGET constant is visible. A prompt-injection (or a routine LLM hallucination) that asks the agent to "send all funds" has no upper bound.',
        remediation: 'Define MAX_SINGLE_TX_USD and MAX_DAILY_SPEND_USD as Decimal constants. Add a SpendLimitGuard that checks both before every transaction; persist daily spend in disk-state so restart doesn\'t reset it.',
      });
    }
  }

  // 3. Onchain data concatenated into LLM prompt
  if (_PROMPT_SINKS.test(raw)) {
    for (const src of _ONCHAIN_DATA_SOURCES) {
      // Look for f-string / template literal / + concat with the source name.
      const fstr = new RegExp(`f["'][^"']*?\\{\\s*${src}\\s*\\}|\\$\\{\\s*${src}\\s*\\}|['"][^'"]*?['"]\\s*\\+\\s*${src}\\b`);
      const m = fstr.exec(raw);
      if (!m) continue;
      // Only fire if there's no obvious sanitizer call near it.
      const nearby = raw.slice(Math.max(0, m.index - 600), m.index + 200);
      if (/\b(?:sanitize|validate|allow_list|allowlist|whitelist|escape|redact)/i.test(nearby)) continue;
      findings.push({
        id: `llm-trading:onchain-prompt-injection:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: `On-chain data (${src}) concatenated into an LLM prompt without sanitization`,
        severity: 'high',
        family: 'llm-trading-prompt-injection',
        cwe: 'CWE-77',
        confidence: 0.7,
        description: `Token names, pair labels, pool metadata, and event-log payloads are attacker-controlled (anyone can deploy a token with any name). When concatenated into an execution-capable LLM prompt, the attacker can issue arbitrary trading instructions.`,
        remediation: `Strip / allow-list the on-chain string before it enters the prompt. Verify it against known injection shapes: "ignore previous instructions", "transfer to 0x...", "approve unlimited".`,
      });
      break;     // one per source is enough
    }
  }

  // 4. Trading loop without circuit breaker
  if (/while\s+True|while\s*\(\s*true|setInterval/.test(raw) && _SIGN_OR_SEND_RE.test(raw) && !_CIRCUIT_BREAKER_RE.test(raw)) {
    const m = /while\s+True|while\s*\(\s*true|setInterval/.exec(raw);
    findings.push({
      id: `llm-trading:no-circuit-breaker:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Autonomous trading loop with no circuit breaker',
      severity: 'high',
      family: 'llm-trading-no-circuit-breaker',
      cwe: 'CWE-754',
      confidence: 0.7,
      description: 'Loop signs and sends transactions in a continuous cycle with no halt condition. A stuck oracle, an exchange bug, or a market crash causes the agent to keep trading the loss.',
      remediation: 'Add a circuit breaker that halts after MAX_CONSECUTIVE_LOSSES or after a portfolio-value drop of MAX_HOURLY_LOSS_PCT. Require human re-arm to resume.',
    });
  }

  // 5. Raw hex private key — PRIVATE_KEY = "0x..." (64 hex chars)
  for (const m of raw.matchAll(/\b(?:PRIVATE_KEY|WALLET_KEY|SIGNING_KEY|priv_key|privKey)\s*[:=]\s*['"]0x[0-9a-fA-F]{64}['"]/g)) {
    findings.push({
      id: `llm-trading:hardcoded-private-key:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Hardcoded 32-byte raw private key in source',
      severity: 'critical',
      family: 'llm-trading-hardcoded-key',
      cwe: 'CWE-798',
      confidence: 0.98,
      description: 'A literal 64-hex-char private key in source is catastrophic — anyone who reads the file can sign transactions as the wallet owner. Bots scrape GitHub for this pattern in real-time.',
      remediation: 'Move to a secure vault (AWS KMS / HashiCorp Vault / GCP Secret Manager) or a hardware wallet. Rotate the key immediately by sweeping funds to a new wallet from a clean machine.',
    });
  }

  return findings;
}
