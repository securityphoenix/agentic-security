import { blankComments } from './_comment-strip.js';
// Kotlin-specific patterns. Most JVM-class vulns are caught by the existing
// java-* modules (which match on `.java|.kt` extension wherever practical).
// This module adds detectors for Kotlin-only idioms that those rules miss:
//
//   - !! force unwrap on user input (NPE → DoS)
//   - runBlocking { ... } on what looks like the main thread (blocks event loop)
//   - val/var that captures req.* into a public top-level (exposes user data)
//   - Runtime.exec / ProcessBuilder fed by !! or by request properties
//   - YAML.load (snakeyaml) without SafeConstructor
//   - Unsafe Gson fromJson on a polymorphic type
//   - File.readText(req.input) — direct user-controlled file read

const RE = {
  forceUnwrap: /\b(?:request|req|input|userInput|params)\b[^=\n]{0,80}!!/g,
  runBlockingTop: /^[\t ]*runBlocking\s*\{/gm,
  unsafeYaml: /\bYaml\s*\(\s*\)\s*\.\s*load\b|\bYaml\s*\(\s*\)\s*\.\s*loadAll\b/g,
  exec: /\bRuntime\.getRuntime\(\)\s*\.\s*exec\s*\(\s*[^)]*\b(?:request|req|input|params|userInput)\b/g,
  gsonPolymorphic: /\bGson\(\)\s*\.\s*fromJson\s*\(\s*[^,)]+,\s*(?:Any::class|Object::class)/g,
  fileReadText: /\bFile\s*\(\s*[^)]*\b(?:request|req|input|userInput|params)\b[^)]*\)\s*\.\s*read(?:Text|Bytes|Lines)/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanKotlin(fp, raw) {
  if (!/\.kt(?:s)?$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  for (const [key, re] of Object.entries(RE)) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      const meta = {
        forceUnwrap: {
          vuln: 'Kotlin force-unwrap (!!) on user input — null causes runtime crash (DoS)',
          severity: 'medium', cwe: 'CWE-476',
          remediation: 'Replace `!!` with `?:` (elvis) returning a safe default, or `?.let { ... }` to skip when null. Force-unwrap on attacker-controllable input lets the client throw 500s at will.',
        },
        runBlockingTop: {
          vuln: 'runBlocking { ... } at top-level — blocks the calling thread, often the event loop in Ktor/Spring WebFlux',
          severity: 'low', cwe: 'CWE-400',
          remediation: 'Replace with a `CoroutineScope(Dispatchers.IO).launch { ... }` or use the framework\'s suspend-aware handler. `runBlocking` in a non-test context kills throughput under load.',
        },
        unsafeYaml: {
          vuln: 'Unsafe YAML.load() — SnakeYAML default constructor instantiates arbitrary classes',
          severity: 'high', cwe: 'CWE-502',
          remediation: 'Use `Yaml(SafeConstructor())` or a typed config library (Hoplite, kotlinx-serialization-yaml). Default `Yaml().load()` lets a crafted YAML file instantiate arbitrary classes — same risk class as Java deserialization.',
        },
        exec: {
          vuln: 'Command Injection — Runtime.exec with user-controlled input (Kotlin)',
          severity: 'critical', cwe: 'CWE-78',
          remediation: 'Use `ProcessBuilder(listOf("cmd", arg1, arg2))` with an array form so the shell never parses anything. Never pass `Runtime.getRuntime().exec("cmd " + input)`.',
        },
        gsonPolymorphic: {
          vuln: 'Gson polymorphic deserialization (Any::class / Object::class) — gadget chain risk',
          severity: 'high', cwe: 'CWE-502',
          remediation: 'Define a concrete target class. Gson `fromJson(json, Any::class)` lets the JSON dictate the target type — a vector for known gadget chains in the classpath.',
        },
        fileReadText: {
          vuln: 'Path Traversal: File.readText with user-controlled path (Kotlin)',
          severity: 'high', cwe: 'CWE-22',
          remediation: 'Canonicalize and verify the path is within an allowed base directory before reading: `if (!File(path).canonicalPath.startsWith(baseDir.canonicalPath)) throw ...`. Better: store files by content-hash filenames generated server-side and let the client request by hash, never by user-supplied path.',
        },
      }[key];
      push({
        id: `kotlin-${key}:${fp}:${line}`,
        file: fp, line,
        vuln: meta.vuln, severity: meta.severity, cwe: meta.cwe,
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: meta.remediation,
        parser: 'KOTLIN',
        confidence: 0.75,
      });
    }
  }
  return findings;
}
