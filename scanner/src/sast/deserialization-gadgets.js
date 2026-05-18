import { blankComments } from './_comment-strip.js';
// Deserialization gadget-chain awareness.
//
// Pure dataflow already flags unsafe deserialization sinks (Java
// ObjectInputStream.readObject, Python pickle.loads, Ruby Marshal.load, PHP
// unserialize, .NET BinaryFormatter). This module sits ON TOP of those:
// when one of those sinks is found *and* the classpath / dependency tree
// shows known gadget libraries (CommonsCollections, Spring AOP, Snakeyaml,
// json-io, etc.), we emit a separate `Deserialization-Gadget-Chain-Present`
// finding with severity bumped to critical.
//
// We do NOT emit on its own — we look for the dep names; the original
// deserialization finding still fires from its module. This module catches
// "yes the library is present, so this is exploitable, not theoretical."

const KNOWN_GADGETS_JAVA = [
  'commons-collections', 'commons-beanutils', 'commons-fileupload',
  'spring-aop', 'spring-core', 'spring-beans',
  'snakeyaml', 'jackson-databind', 'json-io',
  'xstream', 'castor', 'hibernate-core',
];

const KNOWN_GADGETS_PY = [
  'pyyaml', 'jsonpickle', 'dill', 'shelve',
];

const KNOWN_GADGETS_RB = [
  'oj', 'activesupport',  // both have known Marshal gadgets
];

const UNSAFE_SINK_RE = {
  java: /\b(?:ObjectInputStream|XMLDecoder|SerializationUtils\s*\.\s*deserialize|new\s+Yaml\s*\(\s*\))/,
  py: /\b(?:pickle|cPickle|dill|marshal)\s*\.\s*loads?|\byaml\s*\.\s*load\s*\(/,
  rb: /\bMarshal\s*\.\s*load|\bYAML\s*\.\s*load\s*\(|\bOj\s*\.\s*load/,
  php: /\bunserialize\s*\(/,
  cs:  /\bBinaryFormatter|NetDataContractSerializer|SoapFormatter/,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

function detectGadgets(allFileContents) {
  const present = new Set();
  if (!allFileContents) return present;
  // Look in manifests
  const mans = ['package.json', 'pom.xml', 'build.gradle', 'build.gradle.kts',
                'requirements.txt', 'pyproject.toml', 'Pipfile.lock',
                'Gemfile', 'Gemfile.lock', 'composer.json',
                'packages.config'];
  for (const [fp, c] of Object.entries(allFileContents)) {
    const base = fp.split('/').pop();
    if (!mans.includes(base)) continue;
    if (!c || typeof c !== 'string') continue;
    for (const g of KNOWN_GADGETS_JAVA) if (c.includes(g)) present.add(g);
    for (const g of KNOWN_GADGETS_PY) if (c.toLowerCase().includes(g)) present.add(g);
    for (const g of KNOWN_GADGETS_RB) if (c.toLowerCase().includes(g)) present.add(g);
  }
  return present;
}

export function scanDeserializationGadgets(fp, raw, ctx = {}) {
  if (!raw || raw.length > 500_000) return [];
  let lang;
  if (/\.java$/i.test(fp)) lang = 'java';
  else if (/\.py$/i.test(fp)) lang = 'py';
  else if (/\.rb$/i.test(fp)) lang = 'rb';
  else if (/\.php$/i.test(fp)) lang = 'php';
  else if (/\.cs$/i.test(fp)) lang = 'cs';
  else return [];

  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  if (!UNSAFE_SINK_RE[lang].test(code)) return [];

  const gadgets = ctx.gadgets instanceof Set ? ctx.gadgets : detectGadgets(ctx.allFileContents || {});
  if (!gadgets.size) return [];

  // Gate: a known gadget library + an unsafe sink is necessary but not
  // sufficient. We require an EXPLICIT request-source pattern IN THE SAME
  // FILE — request.getParameter, request.getInputStream, etc. — so the
  // exploitable chain is locally evidenced. Files that take byte[] / Stream
  // method parameters (e.g. Juliet's cross-class flow variants 71-84) are
  // NOT enough; many real Java apps pass deser arguments around without
  // those args originating from an attacker.
  const taintSource = /\b(?:request|req)\s*\.\s*(?:getParameter|getHeader|getCookies|getInputStream|getReader|getRequestURI|getQueryString)\b|\bnew\s+(?:Server)?Socket\s*\(/;
  if (!taintSource.test(code)) return [];

  // Emit one informational finding per unsafe-sink-per-file when gadgets are present.
  const findings = [];
  const re = new RegExp(UNSAFE_SINK_RE[lang].source, (UNSAFE_SINK_RE[lang].flags || '') + 'g');
  let m;
  const seen = new Set();
  while ((m = re.exec(code))) {
    const line = lineOf(raw, m.index);
    const id = `deserialize-gadgets:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      file: fp, line,
      vuln: 'Deserialization Gadget-Chain Library Present',
      severity: 'critical',
      cwe: 'CWE-502',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: `An unsafe deserialization sink is present alongside known gadget libraries in the dependency tree (${[...gadgets].slice(0, 4).join(', ')}). This converts the deserialization issue from "theoretical" to "exploitable today" — known exploit payloads exist for these libraries on Maven Central / PyPI. Either drop the deserialization (use a safe format like JSON Schema, protobuf, or msgpack with a known schema) or upgrade past the patched version of the gadget library.`,
      parser: 'DESERIALIZE-GADGETS',
      confidence: 0.90,
      gadgets: [...gadgets],
    });
  }
  return findings;
}

export { detectGadgets as _detectGadgets };
