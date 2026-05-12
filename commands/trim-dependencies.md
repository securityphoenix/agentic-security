---
description: Find and remove installed dependencies that are never imported in source code — reduces attack surface and package bloat.
argument-hint: "[path] [--dry-run] [--include-dev]"
---

Identify installed packages that are never imported anywhere in source code, then generate (and optionally run) the removal commands.

```bash
PATH_ARG="."
DRY_RUN=false
INCLUDE_DEV=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)    DRY_RUN=true ;;
    --include-dev) INCLUDE_DEV=true ;;
    -*) ;;
    *) PATH_ARG="$arg" ;;
  esac
done

node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
  --format json \
  --output .agentic-security/last-scan.json \
  --no-network
```

After the scan completes:

1. Read `.agentic-security/last-scan.json` and extract:
   - `components` — every installed package (has fields: `name`, `version`, `ecosystem`, `scope`, `filePath`)
   - Look for any `imported` array/set in the scan output; if absent, build it yourself by grepping all `.js`, `.jsx`, `.ts`, `.tsx`, `.py` source files under `PATH_ARG` for import/require statements (skip `node_modules/`, `vendor/`, `dist/`, `build/`, `.venv/`, `__pycache__/`).

2. Build the **imported set** by scanning source files if not already in the scan output:
   - **JS/TS:** match `require('pkg')`, `import … from 'pkg'`, `import 'pkg'` — keep the bare package name (e.g. `express` from `express/router`, `@aws-sdk/client-s3` stays as-is for scoped packages).
   - **Python:** match `import pkg`, `from pkg import …` — keep the top-level module name.
   - Normalize all names to lowercase.

3. Determine which packages are **direct** (not transitive):
   - **npm/yarn/pnpm:** the `dependencies` and (if `--include-dev`) `devDependencies` sections of `package.json` files found under `PATH_ARG`. These are the only ones you can safely remove.
   - **pip:** packages listed in `requirements.txt`, `requirements/*.txt`, `pyproject.toml [project.dependencies]`, or `setup.cfg [options] install_requires`. These are the only ones you can safely remove.
   - Transitive deps (in lockfile but not in a manifest's direct section) must be skipped — the package manager handles them.

4. Apply **safe-to-skip** exclusions — never flag these for removal even if they appear unimported:
   - `@types/*` packages (TypeScript declarations, no import needed)
   - Any package referenced in `package.json` `"scripts"` values (CLI tools: `eslint`, `jest`, `ts-node`, `rimraf`, etc.)
   - Any package listed in `peerDependencies` or `peerDependenciesMeta`
   - Any package whose name ends in `-loader`, `-plugin`, `-preset`, `-transform` (often webpack/babel plugins with no explicit import)
   - `dotenv` if a `.env` file exists (commonly loaded via `--require` flag)
   - `source-map-support`, `reflect-metadata`, `tsconfig-paths` (runtime bootstrappers, imported via `-r` flag or `require()` before bundling)
   - Any package explicitly called out in a comment `# trim-dependencies-keep: pkg` anywhere in the project

5. **Compute the bloat list:**
   ```
   bloat = direct_deps ∩ NOT(imported) ∩ NOT(safe_to_skip)
   ```

6. **Measure installed size for each bloat package:**
   - **npm:** for each package in `bloat`, sum the on-disk size of `node_modules/<pkg>/` using `du -sk node_modules/<pkg>` (or `node_modules/@scope/pkg/` for scoped packages). If `node_modules/` is absent (CI environment), fall back to the `size` field from `package-lock.json` if present, otherwise mark as `(size unknown)`.
   - **pip:** run `pip show <pkg>` and capture the `Location:` field, then sum the on-disk size of the package directory. If unavailable, mark as `(size unknown)`.
   - Accumulate a **total savings** figure (sum of all measured sizes). Format sizes as KB or MB (e.g. `2.3 MB`, `840 KB`).
   - Also note the **transitive depth** savings: for each bloat package, count how many entries in the lockfile (`package-lock.json` `packages` section, or `pip freeze` output) exist solely because of that package. Label these as `+N transitive` in the report.

7. **Print the report:**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  agentic-security: trim-dependencies
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Installed (direct):  42 packages
  Imported in source:  27 packages
  Bloat (unimported):   4 packages   ← 9.5% of direct deps

  Estimated savings:   14.2 MB on disk  (+31 transitive packages)

  UNIMPORTED PACKAGES
  ──────────────────────────────────────────────
  npm (package.json)
    lodash           4.17.21    5.8 MB   +0 transitive
    moment           2.29.4     4.7 MB   +3 transitive
    colors           1.4.0     76 KB    +0 transitive

  pip (requirements.txt)
    boto3            1.26.0     3.6 MB   +28 transitive

  ──────────────────────────────────────────────
  Total removable:  4 packages · 14.2 MB · 31 transitive deps

  Removal commands (copy-paste ready):

  npm uninstall lodash moment colors

  pip uninstall -y boto3

  ──────────────────────────────────────────────
  Skipped (safe-to-keep):
    @types/node, jest, eslint, ts-node  (CLI / type-only)
```

8. If `--dry-run` is passed (or omitted): **do not run any removal commands**. Print the commands only.

9. If the user explicitly passes `--apply` (not `--dry-run`): warn that this will modify manifests and ask for confirmation. On confirmation, run each removal command, then re-run the scan to confirm the package list shrank. Warn if any tests fail after removal.

10. If zero bloat packages are found:
```
✅  No unimported direct dependencies found — nothing to trim.
```

🛡  agentic-security · created by ClearCapabilities.Com
