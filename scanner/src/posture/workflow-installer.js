// Workflow installer — detect the project type and emit pre-commit
// hook scripts + CI YAML files tuned to the repo.
//
// Two functions:
//
//   detectProject(scanRoot)
//     Returns { lang, pm, ciProvider, hookManager } based on file probes.
//
//   buildHookConfig(scanRoot, opts)
//     Returns { files: { path: content, ... } } to write — pre-commit
//     hook configuration in whichever style the project already uses
//     (husky / pre-commit / lefthook / native git hooks).
//
//   buildCiConfig(scanRoot, opts)
//     Returns { files: { path: content, ... } } for the chosen CI
//     provider (github-actions / gitlab-ci / circleci / native).
//
// Pure render — caller writes the files and runs install commands.
// No subprocess calls happen inside this module.

import * as fs from 'node:fs';
import * as path from 'node:path';

function _exists(p) { return fs.existsSync(p); }

/**
 * Project-type detection.
 */
export function detectProject(scanRoot) {
  const has = (rel) => _exists(path.join(scanRoot, rel));
  const lang =
    has('package.json')   ? 'node' :
    has('pyproject.toml') || has('requirements.txt') ? 'python' :
    has('Cargo.toml')     ? 'rust' :
    has('go.mod')         ? 'go' :
    has('pom.xml') || has('build.gradle') || has('build.gradle.kts') ? 'java' :
    has('Gemfile')        ? 'ruby' :
    has('composer.json')  ? 'php' :
    'unknown';
  const pm =
    has('yarn.lock')      ? 'yarn' :
    has('pnpm-lock.yaml') ? 'pnpm' :
    has('package-lock.json') ? 'npm' :
    has('poetry.lock')    ? 'poetry' :
    has('Pipfile.lock')   ? 'pipenv' :
    null;
  const ciProvider =
    has('.github/workflows') ? 'github-actions' :
    has('.gitlab-ci.yml')    ? 'gitlab-ci' :
    has('.circleci/config.yml') ? 'circleci' :
    has('Jenkinsfile')       ? 'jenkins' :
    null;
  const hookManager =
    has('.husky')                              ? 'husky' :
    has('.pre-commit-config.yaml')             ? 'pre-commit' :
    has('lefthook.yml') || has('.lefthook.yml') ? 'lefthook' :
    has('.git/hooks')                          ? 'native' :
    null;
  return { lang, pm, ciProvider, hookManager };
}

/**
 * Build pre-commit hook config tuned to the project's chosen hook manager.
 *
 * opts:
 *   severity: 'critical' | 'high' | 'medium' (default 'critical')
 *   diffOnly: true (default) — scan only changed files
 */
export function buildHookConfig(scanRoot, opts = {}) {
  const sev = opts.severity || 'critical';
  const diffOnly = opts.diffOnly !== false;
  const detected = detectProject(scanRoot);
  const cmd = `npx --no-install agentic-security scan ${diffOnly ? '--diff' : ''} --fail-on ${sev}`.replace(/\s+/g, ' ').trim();

  const files = {};
  const manager = detected.hookManager || (detected.lang === 'node' ? 'husky' : 'pre-commit');

  if (manager === 'husky') {
    files['.husky/pre-commit'] = [
      '#!/usr/bin/env sh',
      '. "$(dirname -- "$0")/_/husky.sh"',
      '',
      '# agentic-security: refuse the commit if any new critical finding lands',
      cmd,
      '',
    ].join('\n');
  } else if (manager === 'pre-commit') {
    const cfgPath = '.pre-commit-config.yaml';
    const existing = _exists(path.join(scanRoot, cfgPath)) ? fs.readFileSync(path.join(scanRoot, cfgPath), 'utf8') : 'repos:\n';
    const hookYaml = [
      '  - repo: local',
      '    hooks:',
      '      - id: agentic-security',
      '        name: agentic-security scan (diff)',
      '        entry: ' + cmd,
      '        language: system',
      '        pass_filenames: false',
      '        stages: [pre-commit]',
      '',
    ].join('\n');
    if (!/agentic-security/.test(existing)) files[cfgPath] = existing.trim() + '\n\n' + hookYaml;
  } else if (manager === 'lefthook') {
    const cfgPath = 'lefthook.yml';
    const existing = _exists(path.join(scanRoot, cfgPath)) ? fs.readFileSync(path.join(scanRoot, cfgPath), 'utf8') : 'pre-commit:\n  commands:\n';
    const hookYaml = [
      '  commands:',
      '    agentic-security:',
      '      run: ' + cmd,
      '',
    ].join('\n');
    if (!/agentic-security/.test(existing)) files[cfgPath] = existing.trim() + '\n' + hookYaml;
  } else {
    // Native git hooks fallback.
    files['.git/hooks/pre-commit'] = [
      '#!/usr/bin/env sh',
      '# agentic-security: pre-commit security scan',
      cmd,
      '',
    ].join('\n');
  }
  return { manager, files };
}

/**
 * Build CI workflow config for the chosen provider.
 *
 * opts:
 *   provider: 'github-actions' | 'gitlab-ci' | 'circleci' | 'auto'
 *   schedule: cron string for weekly full scan (default 'Mon 09:00 UTC')
 *   prSeverityFloor: 'critical' (default)
 */
export function buildCiConfig(scanRoot, opts = {}) {
  const detected = detectProject(scanRoot);
  const provider = opts.provider === 'auto' || !opts.provider ? (detected.ciProvider || 'github-actions') : opts.provider;
  const sev = opts.prSeverityFloor || 'critical';

  const files = {};
  if (provider === 'github-actions') {
    files['.github/workflows/agentic-security.yml'] = _githubActions(sev);
  } else if (provider === 'gitlab-ci') {
    files['.gitlab-ci-agentic-security.yml'] = _gitlabCi(sev);
  } else if (provider === 'circleci') {
    files['.circleci/agentic-security.yml'] = _circleCi(sev);
  } else {
    files['ci/agentic-security.sh'] = _nativeShell(sev);
  }
  return { provider, files };
}

function _githubActions(sev) {
  return [
    'name: agentic-security',
    '',
    'on:',
    '  pull_request:',
    '    branches: [main, master, develop]',
    '  push:',
    '    branches: [main, master]',
    '  schedule:',
    '    - cron: "0 9 * * 1"  # Monday 09:00 UTC — full weekly scan',
    '  workflow_dispatch:',
    '',
    'permissions:',
    '  contents: read',
    '  security-events: write',
    '',
    'jobs:',
    '  scan:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v5',
    '        with:',
    '          fetch-depth: 0  # full history for diff baselining',
    "      - uses: actions/setup-node@v5",
    "        with: { node-version: 'lts/*' }",
    '      - name: Run agentic-security',
    '        run: |',
    `          npx -y @clear-capabilities/agentic-security-scanner scan --fail-on ${sev} --sarif > security.sarif`,
    '      - uses: github/codeql-action/upload-sarif@v3',
    '        if: always()',
    '        with: { sarif_file: security.sarif }',
    '',
  ].join('\n');
}

function _gitlabCi(sev) {
  return [
    'agentic-security:',
    '  image: node:lts',
    '  rules:',
    '    - if: $CI_PIPELINE_SOURCE == "merge_request_event"',
    '    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH',
    '  script:',
    `    - npx -y @clear-capabilities/agentic-security-scanner scan --fail-on ${sev} --sarif > security.sarif`,
    '  artifacts:',
    '    paths: [security.sarif]',
    '    reports: { sast: security.sarif }',
    '',
  ].join('\n');
}

function _circleCi(sev) {
  return [
    'version: 2.1',
    'jobs:',
    '  agentic-security:',
    '    docker:',
    '      - image: cimg/node:lts',
    '    steps:',
    '      - checkout',
    '      - run:',
    '          name: agentic-security scan',
    `          command: npx -y @clear-capabilities/agentic-security-scanner scan --fail-on ${sev}`,
    'workflows:',
    '  security:',
    '    jobs: [agentic-security]',
    '',
  ].join('\n');
}

function _nativeShell(sev) {
  return [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    '',
    `npx -y @clear-capabilities/agentic-security-scanner scan --fail-on ${sev}`,
    '',
  ].join('\n');
}

export const _internals = { _exists, _githubActions, _gitlabCi, _circleCi, _nativeShell };
