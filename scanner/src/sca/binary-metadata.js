// Binary artifact SCA metadata extraction.
//
// Reads dependency information from compiled artifacts:
//   - Java JAR files: META-INF/MANIFEST.MF for version + classpath
//   - Go binaries: embedded go.buildinfo for dependency tree
//
// Gated behind AGENTIC_SECURITY_BINARY_SCA=1 (opt-in).
// Does NOT execute binaries — only reads metadata sections.

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

export function isBinaryScaEnabled() {
  return process.env.AGENTIC_SECURITY_BINARY_SCA === '1';
}

// Create a per-extraction temporary directory. Two reasons we can't use
// /tmp directly:
//   1. Permissions — /tmp is shared and a hostile JAR could try to plant a
//      symlinked META-INF/MANIFEST.MF that escapes the scratch dir.
//   2. Concurrency — two parallel extractions on the same jarPath would
//      race on /tmp/META-INF/MANIFEST.MF.
// fs.mkdtempSync atomically allocates a unique dir under the OS temp root;
// the caller is responsible for cleaning it up on every exit path.
function _allocScratchDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'agentic-security-sca-'));
}
function _cleanupScratchDir(dir) {
  if (!dir) return;
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
}

export function extractJarMetadata(jarPath) {
  if (!jarPath || !jarPath.endsWith('.jar')) return null;
  let scratchDir = null;
  try {
    const out = execFileSync('jar', ['tf', jarPath], { encoding: 'utf8', timeout: 5000 });
    const hasManifest = out.includes('META-INF/MANIFEST.MF');
    if (!hasManifest) return null;
    scratchDir = _allocScratchDir();
    execFileSync('jar', ['xf', jarPath, 'META-INF/MANIFEST.MF'], {
      encoding: 'utf8', timeout: 5000, cwd: scratchDir,
    });
    const manifestPath = path.join(scratchDir, 'META-INF', 'MANIFEST.MF');
    if (!fs.existsSync(manifestPath)) return null;
    const content = fs.readFileSync(manifestPath, 'utf8');
    const attrs = {};
    for (const line of content.split('\n')) {
      const m = line.match(/^([A-Za-z-]+):\s*(.+)$/);
      if (m) attrs[m[1].toLowerCase()] = m[2].trim();
    }
    const hasPom = out.includes('pom.properties');
    let groupId = attrs['implementation-vendor-id'] || '';
    let artifactId = attrs['implementation-title'] || path.basename(jarPath, '.jar');
    let version = attrs['implementation-version'] || attrs['bundle-version'] || 'unknown';
    if (hasPom) {
      try {
        const pomFiles = out.split('\n').filter(l => l.includes('pom.properties'));
        if (pomFiles.length) {
          execFileSync('jar', ['xf', jarPath, ...pomFiles], {
            timeout: 5000, cwd: scratchDir,
          });
          for (const pf of pomFiles) {
            const pfPath = path.join(scratchDir, pf);
            if (!fs.existsSync(pfPath)) continue;
            const props = fs.readFileSync(pfPath, 'utf8');
            for (const line of props.split('\n')) {
              if (line.startsWith('groupId=')) groupId = line.split('=')[1].trim();
              if (line.startsWith('artifactId=')) artifactId = line.split('=')[1].trim();
              if (line.startsWith('version=')) version = line.split('=')[1].trim();
            }
            break;
          }
        }
      } catch { /* pom extraction optional */ }
    }
    return {
      name: artifactId,
      version,
      group: groupId,
      ecosystem: 'maven',
      filePath: jarPath,
      scope: 'required',
      purl: `pkg:maven/${groupId}/${artifactId}@${version}`,
      isUnpinned: false,
      _source: 'jar-manifest',
    };
  } catch { return null; }
  finally { _cleanupScratchDir(scratchDir); }
}

export function extractGoBuildInfo(binPath) {
  if (!binPath) return [];
  try {
    const out = execFileSync('go', ['version', '-m', binPath], { encoding: 'utf8', timeout: 5000 });
    const deps = [];
    for (const line of out.split('\n')) {
      const m = line.match(/^\s*dep\s+([\w./-]+)\s+(v[\d.]+(?:-[\w.]+)?)/);
      if (m) {
        deps.push({
          name: m[1],
          version: m[2].replace(/^v/, ''),
          group: '',
          ecosystem: 'golang',
          filePath: binPath,
          scope: 'required',
          purl: `pkg:golang/${m[1]}@${m[2]}`,
          isUnpinned: false,
          _source: 'go-buildinfo',
        });
      }
    }
    return deps;
  } catch { return []; }
}

export function scanBinaryArtifacts(fileContents, scanRoot) {
  if (!isBinaryScaEnabled()) return [];
  const components = [];
  const root = scanRoot || '.';
  try {
    const jarFiles = fs.readdirSync(root, { recursive: true })
      .filter(f => f.endsWith('.jar') && !f.includes('node_modules'))
      .slice(0, 20);
    for (const jar of jarFiles) {
      const meta = extractJarMetadata(path.join(root, jar));
      if (meta) components.push(meta);
    }
  } catch { /* jar scan optional */ }
  try {
    const goBins = fs.readdirSync(root, { recursive: true })
      .filter(f => !f.includes('.') && !f.includes('node_modules') && !f.includes('/'))
      .slice(0, 10);
    for (const bin of goBins) {
      const fp = path.join(root, bin);
      try {
        if (fs.statSync(fp).isFile() && (fs.statSync(fp).mode & 0o111)) {
          components.push(...extractGoBuildInfo(fp));
        }
      } catch { /* skip non-executable */ }
    }
  } catch { /* go binary scan optional */ }
  return components;
}
