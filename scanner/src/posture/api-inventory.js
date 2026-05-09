// 0.7.0 Feat-8: API inventory export — Markdown / JSON / OpenAPI 3.1.
//
// Reuses scan.routes (output of scanRoutes in engine.js). Produces a structured
// API surface map with auth status and data classifications per endpoint.

function _summarize(routes) {
  const total = routes.length;
  const unauth = routes.filter(r => !r.hasAuth).length;
  const dataClasses = {};
  for (const r of routes) for (const c of r.classifications || []) dataClasses[c] = (dataClasses[c] || 0) + 1;
  return { total, authenticated: total - unauth, unauthenticated: unauth, dataClasses };
}

export function toAPIInventoryJSON(scan) {
  const routes = (scan.routes || []).map(r => ({
    method: r.method,
    path: r.path,
    file: r.file,
    line: r.line,
    framework: r.framework || null,
    hasAuth: !!r.hasAuth,
    hasFileUpload: !!r.hasFileUpload,
    parameters: r.params || [],
    dataClasses: r.classifications || [],
    classifiedFields: r.classifiedFields || {},
  }));
  return { summary: _summarize(routes), routes };
}

export function toAPIInventoryMarkdown(scan) {
  const inv = toAPIInventoryJSON(scan);
  const lines = [];
  lines.push(`# API inventory`);
  lines.push('');
  lines.push(`**Total endpoints:** ${inv.summary.total}    **Authenticated:** ${inv.summary.authenticated}    **Unauthenticated:** ${inv.summary.unauthenticated}`);
  lines.push('');
  if (Object.keys(inv.summary.dataClasses).length) {
    lines.push(`**Data classes touched:** ${Object.entries(inv.summary.dataClasses).map(([k,v]) => `${k} (${v})`).join(', ')}`);
    lines.push('');
  }
  lines.push('| Method | Path | Auth | Data classes | File:Line |');
  lines.push('|---|---|---|---|---|');
  // Sort: unauthenticated + data-class first (highest concern), then authenticated.
  const sorted = [...inv.routes].sort((a, b) => {
    const aRisk = (a.hasAuth ? 0 : 10) + (a.dataClasses.length ? 5 : 0);
    const bRisk = (b.hasAuth ? 0 : 10) + (b.dataClasses.length ? 5 : 0);
    return bRisk - aRisk;
  });
  for (const r of sorted) {
    const auth = r.hasAuth ? '🔒' : '⚠️ none';
    const dc = r.dataClasses.join(', ') || '—';
    lines.push(`| \`${r.method}\` | \`${r.path}\` | ${auth} | ${dc} | \`${r.file}:${r.line}\` |`);
  }
  return lines.join('\n');
}

// OpenAPI 3.1 stub. We don't infer request/response schemas (would require
// runtime), but we DO emit the path inventory with security and x-data-classes
// extensions. Useful as a starting point for `swagger-codegen` or as a
// compliance artefact for security questionnaires.
export function toOpenAPI(scan, meta = {}) {
  const inv = toAPIInventoryJSON(scan);
  const paths = {};
  for (const r of inv.routes) {
    const p = r.path || '/';
    paths[p] = paths[p] || {};
    const method = (r.method || 'get').toLowerCase();
    paths[p][method] = {
      operationId: `${method}_${p.replace(/[^A-Za-z0-9]+/g, '_')}_${r.line}`,
      summary: `${r.method} ${r.path}`,
      tags: [r.framework || 'unknown'],
      ...(r.hasAuth ? { security: [{ bearerAuth: [] }] } : {}),
      ...(r.dataClasses.length ? { 'x-agentic-security-data-classes': r.dataClasses } : {}),
      ...(r.hasFileUpload ? { 'x-agentic-security-file-upload': true } : {}),
      'x-source-location': `${r.file}:${r.line}`,
      'x-parameters-detected': r.parameters,
      responses: { '200': { description: 'OK' } },
    };
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'API surface inventory (agentic-security)',
      version: '1.0.0',
      description: `Auto-generated API inventory. ${inv.summary.total} endpoints, ${inv.summary.unauthenticated} unauthenticated.`,
      'x-generated-at': meta.startedAt || new Date().toISOString(),
      'x-generator': 'agentic-security/0.7.0',
    },
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer' },
      },
    },
    paths,
  };
}
