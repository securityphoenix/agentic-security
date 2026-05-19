// Container runtime config audit (FR-XSAT-8).
//
// Flags dangerous combinations in Dockerfile, Kubernetes manifests, and
// ECS task definitions. Each rule names one specific misconfiguration; we
// stay narrow (high precision) and let the curated list grow over time.
//
// Coverage:
//   - Dockerfile          USER root, no USER directive, ADD with URL,
//                         --privileged in HEALTHCHECK
//   - Kubernetes manifest privileged: true, hostNetwork: true,
//                         hostPID: true, runAsUser: 0, allowPrivilegeEscalation: true,
//                         bind-mount of /var/run/docker.sock, capabilities ALL/SYS_ADMIN
//   - ECS task definition privileged: true, host network mode, root user

const DOCKERFILE_NAME_RE = /(?:^|\/)Dockerfile(?:\.[\w.-]+)?$/i;
const K8S_YAML_RE        = /\.(?:ya?ml)$/i;
const ECS_TASK_DEF_RE    = /(?:^|\/)task[-_]?definition[s]?(?:[-_.][\w-]*)?\.json$/i;

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// ─── Dockerfile rules ──────────────────────────────────────────────────────

const DOCKERFILE_RULES = [
  {
    re: /^\s*ADD\s+(?:https?:\/\/|ftp:\/\/)/gmi,
    vuln: 'Dockerfile ADD with remote URL (TLS/MITM exposure; prefer COPY + verified checksum)',
    severity: 'medium', cwe: 'CWE-494', family: 'container-runtime',
  },
  {
    re: /^\s*USER\s+root\b/gmi,
    vuln: 'Dockerfile USER root (container runs with root privileges)',
    severity: 'high', cwe: 'CWE-250', family: 'container-runtime',
  },
  {
    re: /--privileged\b/gi,
    vuln: 'Dockerfile flag --privileged (full host privileges in container)',
    severity: 'critical', cwe: 'CWE-250', family: 'container-runtime',
  },
];

function scanDockerfile(file, raw) {
  const findings = [];
  for (const rule of DOCKERFILE_RULES) {
    const r = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = r.exec(raw))) {
      findings.push(_finding(rule, file, _lineOf(raw, m.index), m[0]));
    }
  }
  // Special check: no USER directive at all.
  if (!/^\s*USER\s+/mi.test(raw)) {
    findings.push(_finding(
      { vuln: 'Dockerfile has no USER directive (defaults to root)', severity: 'medium', cwe: 'CWE-250', family: 'container-runtime' },
      file, 1, '(no USER directive present)'
    ));
  }
  return findings;
}

// ─── Kubernetes manifest rules ────────────────────────────────────────────

const K8S_RULES = [
  { re: /\bprivileged\s*:\s*true\b/gi,                vuln: 'K8s container privileged: true',                 severity: 'critical', cwe: 'CWE-250' },
  { re: /\bhostNetwork\s*:\s*true\b/gi,               vuln: 'K8s pod hostNetwork: true (host network namespace)', severity: 'high',     cwe: 'CWE-732' },
  { re: /\bhostPID\s*:\s*true\b/gi,                   vuln: 'K8s pod hostPID: true (host PID namespace)',     severity: 'high',     cwe: 'CWE-732' },
  { re: /\bhostIPC\s*:\s*true\b/gi,                   vuln: 'K8s pod hostIPC: true (host IPC namespace)',     severity: 'high',     cwe: 'CWE-732' },
  { re: /\ballowPrivilegeEscalation\s*:\s*true\b/gi,  vuln: 'K8s container allowPrivilegeEscalation: true',    severity: 'high',     cwe: 'CWE-250' },
  { re: /\brunAsUser\s*:\s*0\b/gi,                    vuln: 'K8s container runAsUser: 0 (root UID)',           severity: 'high',     cwe: 'CWE-250' },
  // capabilities: add: [ALL] or SYS_ADMIN
  { re: /\badd\s*:\s*\[\s*['"]?ALL['"]?/gi,           vuln: 'K8s securityContext capabilities.add: ALL',       severity: 'critical', cwe: 'CWE-250' },
  { re: /\badd\s*:\s*\[\s*['"]?SYS_ADMIN['"]?/gi,     vuln: 'K8s securityContext capabilities.add: SYS_ADMIN', severity: 'high',     cwe: 'CWE-250' },
  // docker.sock bind-mount
  { re: /\bpath\s*:\s*['"]?\/var\/run\/docker\.sock/gi, vuln: 'K8s hostPath /var/run/docker.sock (container escape primitive)', severity: 'critical', cwe: 'CWE-250' },
  // readOnlyRootFilesystem: false (or missing — only checked when present and false)
  { re: /\breadOnlyRootFilesystem\s*:\s*false\b/gi,   vuln: 'K8s readOnlyRootFilesystem: false (writable root FS)', severity: 'low',  cwe: 'CWE-732' },
];

function scanK8sYaml(file, raw) {
  // Heuristic: looks like a k8s manifest if it has apiVersion + kind.
  if (!/\bapiVersion\s*:/.test(raw) || !/\bkind\s*:/.test(raw)) return [];
  const findings = [];
  for (const rule of K8S_RULES) {
    const r = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = r.exec(raw))) {
      findings.push(_finding({ ...rule, family: 'container-runtime' }, file, _lineOf(raw, m.index), m[0]));
    }
  }
  return findings;
}

// ─── ECS task definition rules ────────────────────────────────────────────

const ECS_RULES = [
  { re: /"privileged"\s*:\s*true\b/g,             vuln: 'ECS container privileged: true',                 severity: 'critical', cwe: 'CWE-250' },
  { re: /"networkMode"\s*:\s*"host"\b/g,          vuln: 'ECS task networkMode: host (host network namespace)', severity: 'high',     cwe: 'CWE-732' },
  { re: /"user"\s*:\s*"(?:root|0)"/g,              vuln: 'ECS container user: root/0',                      severity: 'high',     cwe: 'CWE-250' },
];

function scanEcsTaskDef(file, raw) {
  const findings = [];
  for (const rule of ECS_RULES) {
    const r = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = r.exec(raw))) {
      findings.push(_finding({ ...rule, family: 'container-runtime' }, file, _lineOf(raw, m.index), m[0]));
    }
  }
  return findings;
}

// ─── Common ────────────────────────────────────────────────────────────────

function _finding(rule, file, line, snippet) {
  return {
    id: `container-runtime:${file}:${line}:${(rule.vuln || '').slice(0, 40)}`,
    file, line,
    vuln: rule.vuln,
    severity: rule.severity,
    cwe: rule.cwe || 'CWE-250',
    family: rule.family || 'container-runtime',
    stride: 'Elevation of Privilege',
    parser: 'CONTAINER-RUNTIME',
    confidence: 0.85,
    snippet: typeof snippet === 'string' ? snippet.slice(0, 200) : '',
    remediation: 'Container-runtime misconfig: review the highlighted directive. Default to non-root user, drop all capabilities and add back specifically what you need, set readOnlyRootFilesystem: true, never mount the docker socket, and avoid host namespaces unless explicitly required.',
  };
}

/**
 * Module entry point.
 */
export function scanContainerRuntime(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const out = [];
  for (const [fp, raw] of Object.entries(fileContents)) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 500_000) continue;
    if (DOCKERFILE_NAME_RE.test(fp)) {
      out.push(...scanDockerfile(fp, raw));
    } else if (ECS_TASK_DEF_RE.test(fp)) {
      out.push(...scanEcsTaskDef(fp, raw));
    } else if (K8S_YAML_RE.test(fp)) {
      out.push(...scanK8sYaml(fp, raw));
    }
  }
  return out;
}

export const _internals = { DOCKERFILE_RULES, K8S_RULES, ECS_RULES };
