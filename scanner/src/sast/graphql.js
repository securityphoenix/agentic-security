// GraphQL security detector.
//
// Coverage:
//   1. Query injection — string-concat/template building GraphQL queries from user input
//   2. Depth/complexity DoS — ApolloServer/express-graphql without depth limiting
//   3. Introspection in production — introspection enabled or not explicitly disabled
//   4. Batching DoS — missing batch-size limits
//   5. Field suggestions — error messages leaking field names

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

export function scanGraphQL(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|rb)$/i.test(fp)) return [];

  const findings = [];

  // 1. Query injection: string concat/template into GraphQL query strings
  const queryConcat = /(?:query|mutation)\s*[:=]\s*(?:`[^`]*\$\{[^}]*\}|["'][^"']*["']\s*\+\s*\w)/g;
  for (const m of raw.matchAll(queryConcat)) {
    const ln = _line(raw, m.index);
    const after = raw.slice(m.index, m.index + 300);
    if (/\b(?:gql|graphql|\.query|\.mutate)\b/i.test(after) || /\b(?:query|mutation)\s*\{/.test(after)) {
      findings.push({
        id: `graphql-injection:${fp}:${ln}`,
        file: fp, line: ln,
        vuln: 'GraphQL Query Injection — user input concatenated into query string',
        severity: 'high',
        family: 'graphql-injection',
        cwe: 'CWE-943',
        parser: 'GRAPHQL',
        confidence: 0.75,
        description: 'GraphQL query is built via string concatenation or template interpolation with variables that may contain user input. An attacker can inject additional fields, aliases, or mutations.',
        remediation: 'Use parameterized GraphQL queries with variables: `query GetUser($id: ID!) { user(id: $id) { name } }` and pass variables separately.',
      });
    }
  }

  // 2. Depth/complexity DoS: ApolloServer/createYoga/express-graphql without depth limit
  if (/\b(?:ApolloServer|createYoga|graphqlHTTP|makeExecutableSchema)\b/.test(raw)) {
    if (!/\b(?:depthLimit|graphql-depth-limit|graphql-validation-complexity|costAnalysis|maxDepth|queryDepthLimit)\b/.test(raw)) {
      const m = raw.match(/\b(ApolloServer|createYoga|graphqlHTTP)\b/);
      if (m) {
        findings.push({
          id: `graphql-depth-dos:${fp}:${_line(raw, m.index)}`,
          file: fp, line: _line(raw, m.index),
          vuln: 'GraphQL Depth/Complexity DoS — no depth limiting configured',
          severity: 'medium',
          family: 'graphql-dos',
          cwe: 'CWE-400',
          parser: 'GRAPHQL',
          confidence: 0.70,
          description: 'GraphQL server is configured without query depth or complexity limits. An attacker can send deeply nested queries that exhaust server resources.',
          remediation: 'Add graphql-depth-limit or graphql-query-complexity to validationRules: new ApolloServer({ validationRules: [depthLimit(10)] }).',
        });
      }
    }
  }

  // 3. Introspection in production
  if (/\bintrospection\s*:\s*true\b/.test(raw)) {
    const m = raw.match(/\bintrospection\s*:\s*true\b/);
    if (m) {
      findings.push({
        id: `graphql-introspection:${fp}:${_line(raw, m.index)}`,
        file: fp, line: _line(raw, m.index),
        vuln: 'GraphQL Introspection Enabled — schema exposed to clients',
        severity: 'medium',
        family: 'graphql-introspection',
        cwe: 'CWE-200',
        parser: 'GRAPHQL',
        confidence: 0.80,
        description: 'Introspection is explicitly enabled. Attackers can query __schema to discover all types, fields, and mutations — accelerating further attacks.',
        remediation: 'Disable introspection in production: new ApolloServer({ introspection: process.env.NODE_ENV !== "production" }).',
      });
    }
  }

  // 4. Batching DoS: missing batch limits
  if (/\b(?:ApolloServer|ApolloGateway)\b/.test(raw)) {
    if (!/\b(?:allowBatchedHttpRequests\s*:\s*false|maxBatchSize|batching\s*:\s*false)\b/.test(raw)) {
      const m = raw.match(/\b(ApolloServer|ApolloGateway)\b/);
      if (m) {
        const after = raw.slice(m.index, m.index + 500);
        if (/allowBatchedHttpRequests\s*:\s*true/.test(after) && !/maxBatchSize/.test(after)) {
          findings.push({
            id: `graphql-batch-dos:${fp}:${_line(raw, m.index)}`,
            file: fp, line: _line(raw, m.index),
            vuln: 'GraphQL Batch DoS — batching enabled without size limit',
            severity: 'medium',
            family: 'graphql-dos',
            cwe: 'CWE-400',
            parser: 'GRAPHQL',
            confidence: 0.65,
            description: 'Batched HTTP requests are enabled without a maxBatchSize limit. Attackers can send thousands of operations in a single HTTP request.',
            remediation: 'Set allowBatchedHttpRequests: false, or add maxBatchSize: 10 to limit batch size.',
          });
        }
      }
    }
  }

  // 5. Field suggestions leaking schema info
  if (/\b(?:includeStacktraceInErrorResponses|formatError|debug\s*:\s*true)\b/.test(raw)) {
    if (/\b(?:ApolloServer|graphqlHTTP)\b/.test(raw)) {
      for (const m of raw.matchAll(/\bdebug\s*:\s*true\b/g)) {
        findings.push({
          id: `graphql-debug:${fp}:${_line(raw, m.index)}`,
          file: fp, line: _line(raw, m.index),
          vuln: 'GraphQL Debug Mode — error details exposed to clients',
          severity: 'low',
          family: 'graphql-introspection',
          cwe: 'CWE-209',
          parser: 'GRAPHQL',
          confidence: 0.70,
          description: 'Debug mode exposes stack traces and field suggestion in error responses, leaking internal schema structure.',
          remediation: 'Set debug: false or includeStacktraceInErrorResponses: false in production.',
        });
      }
    }
  }

  return findings;
}
