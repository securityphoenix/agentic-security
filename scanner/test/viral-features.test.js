// v0.72 — viral-feature tests: pr-delta, pr-comment, badge, leaderboard.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { renderPrDeltaText } from '../src/pr-delta.js';
import { renderPrComment, _internal as commentInternal } from '../src/pr-comment.js';
import {
  summarizeForBadge, renderSvg, renderBadge, badgeFromScanRoot, _internal as badgeInternal,
} from '../src/badge.js';
import {
  leaderboardRowFor, rankRows, _internal as lbInternal,
} from '../src/leaderboard.js';

// ─── Badge ─────────────────────────────────────────────────────────────────

test('summarizeForBadge: no findings → passing + green', () => {
  const s = summarizeForBadge({ findings: [] });
  assert.equal(s.summary, 'passing');
  assert.equal(s.highest, 'none');
  assert.equal(s.color, '#4c1');
  assert.equal(s.total, 0);
});

test('summarizeForBadge: critical wins color even when others present', () => {
  const s = summarizeForBadge({ findings: [
    { severity: 'critical' }, { severity: 'high' }, { severity: 'low' },
  ]});
  assert.equal(s.highest, 'critical');
  assert.equal(s.color, '#e05d44');
});

test('summarizeForBadge: no scan returns "no scan" + grey', () => {
  const s = summarizeForBadge(null);
  assert.equal(s.summary, 'no scan');
  assert.equal(s.highest, 'unknown');
});

test('renderSvg produces a valid <svg> with the right text', () => {
  const svg = renderSvg(summarizeForBadge({ findings: [{ severity: 'high' }] }));
  assert.match(svg, /^<svg /);
  assert.match(svg, /<\/svg>$/);
  assert.match(svg, /agentic-security/);
  assert.match(svg, /high 1/);
});

test('renderBadge json format returns shields.io-compatible shape', () => {
  const j = JSON.parse(renderBadge({ format: 'json', scan: { findings: [] } }));
  assert.equal(j.schemaVersion, 1);
  assert.equal(j.label, 'agentic-security');
  assert.equal(j.message, 'passing');
  assert.equal(j.color, '#4c1');
});

test('renderBadge for-the-badge style uses larger height', () => {
  const flat = renderSvg(summarizeForBadge({ findings: [] }), { style: 'flat' });
  const ftb  = renderSvg(summarizeForBadge({ findings: [] }), { style: 'for-the-badge' });
  // for-the-badge has height=28, flat=20.
  assert.match(flat, / height="20"/);
  assert.match(ftb, / height="28"/);
});

test('badgeFromScanRoot reads .agentic-security/last-scan.json', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'badge-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'),
    JSON.stringify({ findings: [{ severity: 'medium' }] }));
  const s = badgeFromScanRoot(dir);
  assert.equal(s.highest, 'medium');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('badge _ageString returns m/h/d', () => {
  const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
  const twoHoursAgo = new Date(Date.now() - 2 * 3600_000).toISOString();
  const threeDaysAgo = new Date(Date.now() - 3 * 86400_000).toISOString();
  assert.match(badgeInternal._ageString(fiveMinAgo), /^\dm ago$/);
  assert.match(badgeInternal._ageString(twoHoursAgo), /^\dh ago$/);
  assert.match(badgeInternal._ageString(threeDaysAgo), /^\dd ago$/);
});

// ─── PR delta text rendering ───────────────────────────────────────────────

test('renderPrDeltaText: zero-delta message says safe to merge', () => {
  const delta = {
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['foo.js'],
    introduced: [], resolved: [], persistent: [], shifted: [],
    summary: { introduced: {}, resolved: {} },
  };
  const text = renderPrDeltaText(delta);
  assert.match(text, /No security delta/);
  assert.match(text, /Safe to merge/);
});

test('renderPrDeltaText: lists introduced findings up to 20', () => {
  const intro = [];
  for (let i = 0; i < 25; i++) intro.push({
    severity: 'high', cwe: 'CWE-89', vuln: `v${i}`, file: 'a.js', line: i,
  });
  const delta = {
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['a.js'],
    introduced: intro, resolved: [], persistent: [], shifted: [],
    summary: {
      introduced: { total: 25, critical: 0, high: 25, medium: 0, low: 0, info: 0 },
      resolved:   { total: 0,  critical: 0, high: 0,  medium: 0, low: 0, info: 0 },
    },
  };
  const text = renderPrDeltaText(delta);
  assert.match(text, /Introduced: 25/);
  assert.match(text, /5 more/);   // 25 - 20 = 5
});

// ─── PR comment rendering ──────────────────────────────────────────────────

test('renderPrComment: zero delta produces a single "safe to merge" paragraph', () => {
  const c = renderPrComment({
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['foo.js'],
    introduced: [], resolved: [], shifted: [],
    base: { summary: { total: 5 } },
    head: { summary: { total: 5 } },
  });
  assert.match(c, /Safe to merge/);
  assert.match(c, /1 file/);
});

test('renderPrComment: resolves-only message is celebratory', () => {
  const c = renderPrComment({
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['foo.js'],
    introduced: [],
    resolved: [{ severity: 'critical', cwe: 'CWE-89', vuln: 'sql' }],
    shifted: [],
    summary: { resolved: { critical: 1, high: 0 }, introduced: {} },
  });
  assert.match(c, /\*\*resolves\*\* 1 finding/);
  assert.match(c, /Nice cleanup/);
});

test('renderPrComment: needs-work mode produces advisor prose + per-finding paragraphs', () => {
  const c = renderPrComment({
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['app.js'],
    introduced: [
      { severity: 'high', cwe: 'CWE-89', vuln: 'SQL Injection', file: 'app.js', line: 14, remediation: 'Use parameterized queries.' },
      { severity: 'medium', cwe: 'CWE-79', vuln: 'XSS', file: 'app.js', line: 22 },
    ],
    resolved: [],
    shifted: [],
    summary: {
      introduced: { critical: 0, high: 1, medium: 1 },
      resolved: {},
    },
  }, { repoName: 'org/repo', prNumber: 42, prTitle: 'add admin route' });
  assert.match(c, /org\/repo#42/);
  assert.match(c, /2 new finding/);
  assert.match(c, /SQL injection/);                // CWE narrative
  assert.match(c, /dump every row/);                // CWE 'why' text
  assert.match(c, /Use parameterized queries/);     // remediation shown
});

test('renderPrComment: critical/high introduced → blocking-merge footer', () => {
  const c = renderPrComment({
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['a.js'],
    introduced: [{ severity: 'critical', cwe: 'CWE-78', vuln: 'cmd', file: 'a.js', line: 1 }],
    resolved: [], shifted: [],
    summary: { introduced: { critical: 1, high: 0 }, resolved: {} },
  });
  assert.match(c, /Blocking merge/);
});

test('renderPrComment: top-3 CWE families summary appears', () => {
  const intro = [];
  for (let i = 0; i < 4; i++) intro.push({ severity: 'high', cwe: 'CWE-89', vuln: 'sqli', file: 'f', line: i });
  for (let i = 0; i < 2; i++) intro.push({ severity: 'medium', cwe: 'CWE-79', vuln: 'xss', file: 'f', line: 10 + i });
  const c = renderPrComment({
    baseRef: 'main', headRef: 'HEAD',
    changedFiles: ['f.js'],
    introduced: intro, resolved: [], shifted: [],
    summary: { introduced: { critical: 0, high: 4 }, resolved: {} },
  });
  // Top: 4 SQL injection, 2 XSS
  assert.match(c, /4 SQL injection/);
  assert.match(c, /2 XSS/);
});

// ─── Leaderboard ───────────────────────────────────────────────────────────

test('_postureGrade: maps severity counts to A-F', () => {
  assert.equal(lbInternal._postureGrade({ critical: 0, high: 0, medium: 0 }), 'A');
  assert.equal(lbInternal._postureGrade({ critical: 0, high: 0, medium: 3 }), 'B');
  assert.equal(lbInternal._postureGrade({ critical: 0, high: 2 }), 'C');
  assert.equal(lbInternal._postureGrade({ critical: 1, high: 1 }), 'D');
  assert.equal(lbInternal._postureGrade({ critical: 5, high: 10 }), 'F');
});

test('leaderboardRowFor: builds a row from last-scan.json', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lb-'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'),
    JSON.stringify({
      timestamp: new Date(Date.now() - 3600_000).toISOString(),
      findings: [
        { severity: 'high', cwe: 'CWE-89' },
        { severity: 'high', cwe: 'CWE-89' },
        { severity: 'medium', cwe: 'CWE-79' },
      ],
    }));
  const row = leaderboardRowFor({ scanRoot: dir, repo: 'acme/widget' });
  assert.equal(row.repo, 'acme/widget');
  assert.equal(row.score.high, 2);
  assert.equal(row.topCwe, 'CWE-89');
  assert.equal(row.postureGrade, 'C');
  assert.match(row.lastScanAge, /^\dh$/);
  assert.match(row.badgeUrl, /acme%2Fwidget/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('rankRows: lower critical count wins, ties broken by high then grade', () => {
  const rows = [
    { repo: 'a', score: { critical: 1, high: 0 }, postureGrade: 'D' },
    { repo: 'b', score: { critical: 0, high: 5 }, postureGrade: 'C' },
    { repo: 'c', score: { critical: 0, high: 0 }, postureGrade: 'A' },
    { repo: 'd', score: { critical: 0, high: 0 }, postureGrade: 'B' },
  ];
  const ranked = rankRows(rows);
  assert.equal(ranked[0].repo, 'c');           // A grade wins
  assert.equal(ranked[1].repo, 'd');           // B grade next
  assert.equal(ranked[2].repo, 'b');           // C grade
  assert.equal(ranked[3].repo, 'a');           // critical=1 last
  for (let i = 0; i < ranked.length; i++) assert.equal(ranked[i].rank, i + 1);
});

test('_topCwes returns the top families in order', () => {
  const findings = [
    { cwe: 'CWE-89' }, { cwe: 'CWE-89' }, { cwe: 'CWE-89' },
    { cwe: 'CWE-79' }, { cwe: 'CWE-79' },
    { cwe: 'CWE-22' },
  ];
  const top = commentInternal._topCwes(findings);
  assert.equal(top[0][0], 'CWE-89');
  assert.equal(top[0][1], 3);
  assert.equal(top[1][0], 'CWE-79');
});
