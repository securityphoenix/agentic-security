// POSITIVE: TOCTOU — existsSync then readFileSync on the same path.
import fs from 'node:fs';

export function readConfig(path) {
  if (fs.existsSync(path)) {
    return fs.readFileSync(path, 'utf8');
  }
  return null;
}
