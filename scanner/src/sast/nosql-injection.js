import { blankComments } from './_comment-strip.js';
// NoSQL injection (MongoDB / Mongoose / DynamoDB / etc.).
//
// Three classes:
//   1. MongoDB $where with a string built from user input — equivalent to
//      arbitrary JS evaluation on the server.
//   2. Mongoose / mongo find(req.body) — Mongo accepts operator objects in
//      values, so `{ password: { $ne: null } }` matches any record. The fix
//      is to coerce the value to a string before passing it in.
//   3. DynamoDB FilterExpression / ConditionExpression / KeyConditionExpression
//      built via string concat instead of placeholders.

const MONGO_WHERE_RE = /\$where\s*:\s*[^,}]*(?:\+|`\$\{|String\(|String\.raw)/g;

const MONGO_FIND_REQ_OBJ_RE = /\.\s*(?:find|findOne|findOneAndUpdate|findOneAndDelete|update|updateOne|updateMany|deleteOne|deleteMany|count|countDocuments)\s*\(\s*(?:req|request|ctx\.request)\s*\.\s*(?:body|query|params)\s*[,)]/g;

const DYNAMO_EXPR_CONCAT_RE = /(?:FilterExpression|ConditionExpression|KeyConditionExpression|UpdateExpression)\s*:\s*[^,}]*[`+][^,}]*\$\{?\s*(?:req|request)\s*\./g;

const PY_MONGO_FIND_REQ = /\.\s*(?:find|find_one|update_one|update_many|delete_one|delete_many)\s*\(\s*request\s*\.\s*(?:json|data|args|form)/g;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanNoSQLInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) {
    const code = blankComments(raw);
    let m;
    for (const [re, key, label, conf] of [
      [MONGO_WHERE_RE, 'mongo-where', 'NoSQL Injection: MongoDB $where with user-controlled string', 0.90],
      [MONGO_FIND_REQ_OBJ_RE, 'mongo-find', 'NoSQL Injection: MongoDB query with raw request object (operator injection)', 0.80],
      [DYNAMO_EXPR_CONCAT_RE, 'dynamo-expr', 'NoSQL Injection: DynamoDB Expression built via string concatenation', 0.85],
    ]) {
      const r = new RegExp(re.source, re.flags);
      while ((m = r.exec(code))) {
        const line = lineOf(raw, m.index);
        push({
          id: `nosql-${key}:${fp}:${line}`,
          file: fp, line,
          vuln: label,
          severity: 'high',
          cwe: 'CWE-943',
          stride: 'Tampering',
          snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
          remediation: key === 'mongo-where'
            ? '`$where` runs server-side JavaScript and treats any string as code. Replace with structural operators (`$expr`, `$gt`, `$regex` with a constant pattern). Never build a `$where` string from user input.'
            : key === 'mongo-find'
            ? 'Coerce each value to a primitive before passing into Mongo: `await User.findOne({ email: String(req.body.email), password: hash(String(req.body.password)) })`. Mongo accepts operator objects as values — `{ $ne: null }` matches every record.'
            : 'Build DynamoDB expressions with ExpressionAttributeValues placeholders, never via string concatenation: `KeyConditionExpression: "id = :id", ExpressionAttributeValues: { ":id": userId }`.',
          parser: 'NOSQL-INJECTION',
          confidence: conf,
        });
      }
    }
  }

  if (/\.py$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    let m;
    const r = new RegExp(PY_MONGO_FIND_REQ.source, PY_MONGO_FIND_REQ.flags);
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      push({
        id: `nosql-pymongo:${fp}:${line}`,
        file: fp, line,
        vuln: 'NoSQL Injection: PyMongo query with raw request body',
        severity: 'high',
        cwe: 'CWE-943',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Construct the query dict yourself with coerced values: `users.find_one({"email": str(request.json["email"])})`. Passing `request.json` directly lets a client smuggle operator dicts (`{"$ne": null}`) that match every record.',
        parser: 'NOSQL-INJECTION',
        confidence: 0.80,
      });
    }
  }

  return findings;
}
