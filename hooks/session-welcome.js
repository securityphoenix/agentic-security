#!/usr/bin/env node
// SessionStart hook.
//
// First session per project: print full welcome + commands list.
// Subsequent sessions: print a one-line streak greeting if there's a streak
// (e.g., "🔥 14 days clean of critical findings · grade A · 12 fixes applied").
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const marker = path.join(stateDir, '.welcomed');
const streakPath = path.join(stateDir, 'streak.json');

function loadStreak() {
  try { return JSON.parse(fs.readFileSync(streakPath, 'utf8')); }
  catch { return null; }
}

function formatStreakLine(s) {
  if (!s || !s.totalScans) return null;
  const parts = [];
  if (s.daysCleanCritical >= 1) {
    const flame = s.daysCleanCritical >= 7 ? '🔥 ' : '';
    parts.push(`${flame}${s.daysCleanCritical} day${s.daysCleanCritical === 1 ? '' : 's'} clean of critical findings`);
  }
  if (s.lastGrade) parts.push(`grade ${s.lastGrade}`);
  if (s.totalFixesInferred > 0) parts.push(`${s.totalFixesInferred} fix${s.totalFixesInferred === 1 ? '' : 'es'} applied`);
  return parts.length ? parts.join(' · ') : null;
}

const isFirstTime = !fs.existsSync(marker);

if (isFirstTime) {
  const lines = [
    '',
    '🔒 agentic-security is active in this project.',
    '',
    '  /security-scan-all     full SAST + SCA + secrets + IaC sweep',
    '  /security-grade        single A-F grade with one-sentence reason',
    '  /security-launch-check pre-deploy 10-item checklist',
    '  /security-help         see all 33 commands by category',
    '  /security-status       project health & plugin status',
    '',
    '  Hooks: every Edit/Write scans the changed file in <5s.',
    '  This welcome shows once per project.',
    '',
  ];
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(marker, new Date().toISOString());
  } catch {}
  console.error(lines.join('\n'));
  process.exit(0);
}

// Returning session: print streak greeting if we have one
const streak = loadStreak();
const line = formatStreakLine(streak);
if (line) {
  console.error('🛡️  ' + line);
}
process.exit(0);
