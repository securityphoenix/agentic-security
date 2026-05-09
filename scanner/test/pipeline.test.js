// 0.7.0 Feat-9: Pipeline / GH Actions integrity — F1 over labelled fixtures.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

// Note: fixture dir scoped to the parent so the `.github/workflows/` prefix is
// preserved in the relative path the detector matches against.
const LABELS = [
  { file: '.github/workflows/vuln-floating-tag.yml',     positive: true,  matcher: /floating tag/i },
  { file: '.github/workflows/vuln-write-all.yml',        positive: true,  matcher: /write-all/i },
  { file: '.github/workflows/vuln-secret-echo.yml',      positive: true,  matcher: /secret echoed/i },
  { file: '.github/workflows/vuln-script-injection.yml', positive: true,  matcher: /untrusted github\.event/i },
  { file: '.github/workflows/vuln-oidc-no-aud.yml',      positive: true,  matcher: /OIDC.*aud/i },
  { file: '.github/workflows/vuln-major-tag.yml',        positive: true,  matcher: /major-version tag/i },
  { file: '.github/workflows/safe-pinned.yml',           positive: false, matcher: /Pipeline:/i },
  { file: '.github/workflows/safe-min-perms.yml',        positive: false, matcher: /Pipeline:/i },
  { file: '.github/workflows/safe-oidc-with-aud.yml',    positive: false, matcher: /OIDC.*aud/i },
];

test('Pipeline integrity — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Pipeline-detector',
    fixtureDir: 'pipeline-integrity',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});
