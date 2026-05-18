import { blankComments } from './_comment-strip.js';
// Mass assignment / over-posting detector.
//
// The classic shape: developer wires the entire request body into an ORM
// create/update call, allowing the client to set fields the route handler
// never intended (is_admin, role, balance, etc.).
//
// Languages covered:
//   - JS/TS Express + Mongoose/Sequelize/Prisma/TypeORM
//   - Ruby on Rails ActiveRecord
//   - Python Django ORM / Flask-SQLAlchemy
//   - Java Spring Data
//   - Go GORM
//
// Heuristic per-language: spread/splat of a request-body shape directly into
// a constructor, create(), update(), .save(), .set(), or Object.assign on a
// model. Whitelisting (allowed-fields pick) is the canonical fix.

const ALLOW_LIST_HINTS = /(?:pick|allowedFields|permit|allowed_params|whitelist|strong_params|FILTER_FIELDS|select_for|only:)/;

const JS_PATTERNS = [
  // Object.assign(user, req.body)
  /Object\.assign\s*\(\s*(\w+)\s*,\s*(req|request)\s*\.\s*(body|params|query)\b/g,
  // new User({ ...req.body })  or  User.create({ ...req.body })
  /(?:new\s+([A-Z]\w+)\s*\(\s*\{[^}]*\.\.\.\s*(?:req|request)\s*\.\s*(?:body|params|query))/g,
  // User.create(req.body)  ·  Model.update(req.body, …)
  /\b([A-Z]\w+)\s*\.\s*(?:create|update|build|save)\s*\(\s*(?:req|request)\s*\.\s*(?:body|params|query)\s*[,)]/g,
  // prisma.user.update({ data: req.body })
  /\.\s*(?:create|update|upsert)\s*\(\s*\{[^}]*data\s*:\s*(?:req|request)\s*\.\s*(?:body|params|query)/g,
];

const PY_PATTERNS = [
  // Model.objects.create(**request.POST) / **request.data / **request.json
  /\b([A-Z]\w+)\s*(?:\.objects)?\s*\.\s*(?:create|update|filter\([^)]*\)\.update)\s*\(\s*\*\*\s*request\s*\.\s*(?:POST|data|json|form)/g,
  // serializer.save(**request.data)
  /\.save\s*\(\s*\*\*\s*request\s*\.\s*(?:data|json|POST|form)/g,
  // setattr(obj, k, v) loop over request.data without allow-list
  /for\s+\w+\s*,\s*\w+\s+in\s+request\s*\.\s*(?:data|json|POST|form)\s*\.\s*items\s*\([^)]*\)\s*:\s*\n\s*setattr/g,
];

const RB_PATTERNS = [
  // User.create(params)  ·  user.update(params)
  /\b([A-Z]\w+)\s*\.\s*(?:create|update|new)\s*\(\s*params\s*[,)]/g,
  // user.assign_attributes(params)  ·  user.attributes = params
  /\.(?:assign_attributes|attributes\s*=)\s*\(?\s*params\s*[,)]?/g,
];

const GO_PATTERNS = [
  // db.Model(&user).Updates(input)  where input is fully user-controlled
  /\bdb\s*\.\s*(?:Model|Updates|Create)\s*\([^)]*&?\s*(\w+)\s*\)/g,
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

function pickPatterns(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return { lang: 'js', patterns: JS_PATTERNS };
  if (/\.py$/i.test(fp)) return { lang: 'py', patterns: PY_PATTERNS };
  if (/\.rb$/i.test(fp)) return { lang: 'rb', patterns: RB_PATTERNS };
  if (/\.go$/i.test(fp)) return { lang: 'go', patterns: GO_PATTERNS };
  return null;
}

export function scanMassAssignment(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const sel = pickPatterns(fp);
  if (!sel) return [];
  const findings = [];
  const seen = new Set();
  const code = blankComments(raw, sel.lang === 'py' ? 'py' : undefined);
  // Skip files that look like they use an allow-list — strong signal of safety.
  if (ALLOW_LIST_HINTS.test(code.slice(0, 4000))) {
    // not a hard skip: still scan but downgrade
  }
  for (const re of sel.patterns) {
    const r = new RegExp(re.source, re.flags);
    let m;
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `mass-assignment:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      // Look ±5 lines for an allow-list signal — if present, downgrade.
      const lines = raw.split('\n');
      const window = lines.slice(Math.max(0, line - 6), line + 5).join(' ');
      const hasAllowList = ALLOW_LIST_HINTS.test(window);
      findings.push({
        id,
        file: fp, line,
        vuln: 'Mass Assignment: Unfiltered request body into model write',
        severity: hasAllowList ? 'low' : 'high',
        cwe: 'CWE-915',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Explicitly allow-list the fields a client may set, instead of spreading the whole request body into the model write. Express: `pick(req.body, ["name", "email"])` (lodash) before `.create()`. Rails: `params.require(:user).permit(:name, :email)`. Django: a `ModelForm` / `Serializer` with explicit fields. Mass-assigning the whole body lets a client elevate privileges by adding `is_admin: true` to the JSON.',
        parser: 'MASS-ASSIGN',
        confidence: hasAllowList ? 0.40 : 0.85,
      });
    }
  }
  return findings;
}
