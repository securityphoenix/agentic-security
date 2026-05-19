// Multi-harness configuration discovery.
//
// Finds every agent-harness configuration directory the user has, both at
// the project root AND under ~/. The discovered files feed the
// claude-settings / claude-md-prompt-injection / claude-hook-injection
// detectors so we audit Claude / Cursor / Codex / Gemini / Kiro / OpenCode /
// Trae / Qwen / Zed / Continue / Aider with one sweep.
//
// Used by the `/scan --harness` mode.

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';

export const HARNESS_DIRS = [
  '.claude', '.cursor', '.codex', '.gemini', '.kiro',
  '.opencode', '.trae', '.qwen', '.zed', '.continue', '.aider',
  '.codebuddy', '.copilot',
];

const HARNESS_FILES = [
  // settings + permissions
  'settings.json', 'settings.local.json', 'config.json',
  // instruction files (lifted into context every session)
  'CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'CURSOR.md', 'CODEX.md',
  'KIRO.md', 'QWEN.md', 'TRAE.md', 'OPENCODE.md', 'SYSTEM_PROMPT.md',
  // mcp
  'mcp.json', '.mcp.json', 'mcp_servers.json', 'claude_desktop_config.json',
  // hooks
  'hooks.json', 'hooks.yml', 'hooks.yaml',
];

const HARNESS_SUBDIRS = ['agents', 'skills', 'commands', 'hooks', 'rules'];

const MAX_FILE_SIZE = 1_000_000;

async function _readSafe(fp) {
  try {
    const stat = await fs.stat(fp);
    if (stat.size > MAX_FILE_SIZE) return null;
    return await fs.readFile(fp, 'utf8');
  } catch { return null; }
}

async function _walkHarnessDir(harnessRoot, harnessName, out) {
  // Top-level config files.
  for (const fn of HARNESS_FILES) {
    const fp = path.join(harnessRoot, fn);
    const content = await _readSafe(fp);
    if (content !== null) out[fp] = content;
  }
  // Subdirs holding instruction-style files.
  for (const sub of HARNESS_SUBDIRS) {
    const dp = path.join(harnessRoot, sub);
    try {
      const entries = await fs.readdir(dp, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isFile()) continue;
        if (!/\.(?:md|json|yaml|yml)$/i.test(e.name)) continue;
        const fp = path.join(dp, e.name);
        const content = await _readSafe(fp);
        if (content !== null) out[fp] = content;
      }
    } catch { /* dir does not exist — fine */ }
  }
  // Project-root CLAUDE.md / AGENTS.md (some users put them outside .claude/).
  // Only walked when the harness is .claude.
  void harnessName;
}

// Discover harness configs at one of:
//   1. The project root (e.g. /path/to/repo/.claude, /path/to/repo/.cursor)
//   2. Home directory (e.g. ~/.claude, ~/.cursor) — opt-in via includeHome=true
export async function discoverHarnessConfigs(projectRoot, opts = {}) {
  const includeHome = !!opts.includeHome;
  const out = {};

  // Project-rooted instruction files commonly placed at repo root.
  for (const fn of ['CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'CURSOR.md', 'CODEX.md', 'KIRO.md', 'QWEN.md', 'TRAE.md', 'OPENCODE.md']) {
    const fp = path.join(projectRoot, fn);
    const content = await _readSafe(fp);
    if (content !== null) out[fp] = content;
  }

  for (const dir of HARNESS_DIRS) {
    const harnessRoot = path.join(projectRoot, dir);
    try { await fs.access(harnessRoot); } catch { continue; }
    await _walkHarnessDir(harnessRoot, dir, out);
  }

  if (includeHome) {
    const home = os.homedir();
    if (home) {
      for (const dir of HARNESS_DIRS) {
        const harnessRoot = path.join(home, dir);
        try { await fs.access(harnessRoot); } catch { continue; }
        await _walkHarnessDir(harnessRoot, dir, out);
      }
    }
  }

  return out;
}

// Inventory of which harnesses are present (for grade / summary).
export function summarizeHarnessPresence(fileContents) {
  const present = new Set();
  for (const fp of Object.keys(fileContents || {})) {
    const m = /\.(claude|cursor|codex|gemini|kiro|opencode|trae|qwen|zed|continue|aider|codebuddy|copilot)[\\/]/.exec(fp);
    if (m) present.add(m[1]);
  }
  return [...present].sort();
}
