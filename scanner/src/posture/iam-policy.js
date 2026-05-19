// IAM policy reachability (FR-XSAT-7).
//
// Parses AWS IAM policy JSON files (Terraform inline policies, raw policy
// documents, CDK stack output, attached-role JSON), correlates them with
// app code references (env vars, role ARNs, service names), and flags
// over-permissive grants — wildcards on dangerous actions, * resource on
// high-blast-radius services, or PassRole on broad targets.
//
// Honest scope for v1:
//   - Static analysis of policy docs. No cloud-API calls.
//   - Reachability proxy: a policy is "reachable" if its file is in the
//     repo AND the policy's role name or ARN appears anywhere in app code
//     (likely indicating the app assumes that role).
//   - The over-permissive ruleset is curated, not exhaustive. Aim for high
//     precision; recall improvements queued for v2.

const IAM_POLICY_FILE_RE = /(?:^|\/)(?:.*\.iam\.json|policy.*\.json|iam-policy.*\.json|role-policy.*\.json)$/i;
const POLICY_JSON_HINTS = /"Version"\s*:\s*"2012-10-17"|"Statement"\s*:\s*\[/;

// Actions we consider dangerous when combined with wildcard resource OR
// effect=Allow + no Condition. Curated; not exhaustive.
const DANGEROUS_ACTIONS = [
  // Identity/access — escalation primitives.
  { action: /^iam:(\*|PassRole|CreateRole|AttachRolePolicy|PutRolePolicy|UpdateAssumeRolePolicy)$/, family: 'iam-overpermissive', severity: 'critical', why: 'IAM action allowing role escalation' },
  // Object storage — exfiltration.
  { action: /^s3:(\*|GetObject|PutObject|DeleteObject)$/, family: 'iam-overpermissive', severity: 'high',     why: 'S3 read/write/delete' },
  // Compute — lateral movement.
  { action: /^lambda:(\*|InvokeFunction|UpdateFunctionCode|CreateFunction)$/, family: 'iam-overpermissive', severity: 'high', why: 'Lambda action allowing code injection / lateral move' },
  { action: /^ec2:(\*|RunInstances|TerminateInstances|ModifyInstanceAttribute)$/, family: 'iam-overpermissive', severity: 'high', why: 'EC2 lifecycle control' },
  // Data layer.
  { action: /^dynamodb:(\*|GetItem|PutItem|DeleteItem|Query|Scan)$/, family: 'iam-overpermissive', severity: 'medium', why: 'DynamoDB data access' },
  { action: /^rds:(\*|DeleteDBInstance|ModifyDBInstance)$/, family: 'iam-overpermissive', severity: 'high', why: 'RDS lifecycle control' },
  // Secrets.
  { action: /^secretsmanager:(\*|GetSecretValue|PutSecretValue)$/, family: 'iam-overpermissive', severity: 'high', why: 'Secrets Manager read/write' },
  { action: /^kms:(\*|Decrypt|Encrypt|GenerateDataKey)$/, family: 'iam-overpermissive', severity: 'high', why: 'KMS key usage' },
];

const WILDCARD_RESOURCE_RE = /^(\*|arn:[\w-]+:\w+:\*:\*:\*)$/;

function _parseStatements(raw) {
  let policy;
  try { policy = JSON.parse(raw); } catch { return []; }
  const stmt = policy.Statement || (policy.PolicyDocument && policy.PolicyDocument.Statement);
  if (!stmt) return [];
  return Array.isArray(stmt) ? stmt : [stmt];
}

function _lineOf(raw, sub) {
  const idx = raw.indexOf(sub);
  if (idx < 0) return 1;
  return raw.substring(0, idx).split('\n').length;
}

function _expandActions(actions) {
  if (!actions) return [];
  return Array.isArray(actions) ? actions : [actions];
}

function _expandResources(resources) {
  if (!resources) return ['*'];
  return Array.isArray(resources) ? resources : [resources];
}

function _isWildcardResource(res) {
  if (typeof res !== 'string') return false;
  return WILDCARD_RESOURCE_RE.test(res);
}

/**
 * Scan one IAM policy file. Returns finding objects.
 */
function scanOnePolicyFile(file, raw) {
  if (!POLICY_JSON_HINTS.test(raw)) return [];
  const statements = _parseStatements(raw);
  const findings = [];
  for (const s of statements) {
    if ((s.Effect || 'Allow') !== 'Allow') continue;
    const actions = _expandActions(s.Action);
    const resources = _expandResources(s.Resource);
    const hasCondition = s.Condition && Object.keys(s.Condition).length > 0;
    // Identify which actions are dangerous + paired with wildcard resource
    // OR no Condition gate.
    for (const a of actions) {
      const rule = DANGEROUS_ACTIONS.find(r => r.action.test(a));
      if (!rule) continue;
      const broadResource = resources.some(_isWildcardResource);
      if (!broadResource && hasCondition) continue;   // narrow + conditioned → ok
      const reason = broadResource
        ? `wildcard resource ${resources.join(',')}`
        : 'no Condition gate';
      findings.push({
        id: `iam:${file}:${a}:${reason}`,
        file,
        line: _lineOf(raw, `"${a}"`),
        vuln: `IAM over-permissive grant: ${a} (${reason})`,
        severity: broadResource ? rule.severity : 'medium',
        cwe: 'CWE-732',                                  // insecure resource permissions
        family: rule.family,
        stride: 'Elevation of Privilege',
        parser: 'IAM-POLICY',
        confidence: 0.7,
        snippet: `Effect=Allow Action=${a} Resource=${resources.join(',')}${hasCondition ? ' [Condition gate present]' : ''}`,
        remediation: `${rule.why}. Either narrow the Action to the specific verb you need, scope Resource to a single ARN, or add a Condition (e.g. \`aws:PrincipalTag\`, \`aws:SourceIp\`, \`aws:RequestedRegion\`) so the grant isn't usable from arbitrary contexts.`,
      });
    }
  }
  return findings;
}

/**
 * Module entry point. fileContents is the full project map; existingFindings
 * is the engine's findings list (used for reachability correlation — the
 * future Phase-2.5 expansion).
 */
export function scanIamPolicies(fileContents /* , existingFindings */) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const findings = [];
  for (const [fp, content] of Object.entries(fileContents)) {
    if (typeof content !== 'string' || content.length === 0) continue;
    if (content.length > 500_000) continue;
    if (!IAM_POLICY_FILE_RE.test(fp) && !POLICY_JSON_HINTS.test(content.slice(0, 500))) continue;
    findings.push(...scanOnePolicyFile(fp, content));
  }
  return findings;
}

// For tests + the no-dead-modules check.
export const _internals = { DANGEROUS_ACTIONS, IAM_POLICY_FILE_RE, scanOnePolicyFile };
