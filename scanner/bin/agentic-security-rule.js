#!/usr/bin/env node
// agentic-security-rule — CLI for signing / verifying custom rule packs.
//
// Subcommands:
//   keygen                Generate an Ed25519 key pair (PRIVATE KEY printed
//                         to stdout; handle with care).
//   sign <rule-yml>       Sign the rule file. Writes <rule-yml>.sig.
//                         Reads the private key from $AGENTIC_SECURITY_PRIVATE_KEY
//                         or --key <base64>.
//   verify <rule-yml>     Verify against the project's trusted-keys.json
//                         (or bundled official keys). Honors revocation.
//
// First-time setup walkthrough:
//
//   1) Generate a key pair OUTSIDE the project tree:
//        mkdir -p ~/.config/agentic-security/keys
//        agentic-security-rule keygen --out ~/.config/agentic-security/keys/MY_KEY.json
//      (the file is written 0600. KEEP the private key SECRET — do not commit it,
//       do not put it in a cloud-synced directory.)
//
//   2) Add the public key to .agentic-security/trusted-keys.json:
//        {
//          "keys": [
//            { "id": "my-team-2026", "alg": "ed25519",
//              "publicKey": "<paste publicKey from step 1>" }
//          ]
//        }
//
//   3) Tell the scanner to trust project-local keys (audit-logged):
//        export AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1
//
//   4) Author a custom rule at .agentic-security/rules/my-rule.yml.
//
//   5) Sign it:
//        export AGENTIC_SECURITY_PRIVATE_KEY="<paste privateKey from step 1>"
//        agentic-security-rule sign .agentic-security/rules/my-rule.yml
//
//   6) Verify before commit:
//        agentic-security-rule verify .agentic-security/rules/my-rule.yml
//
// CAUTION: the private key in step 1 is a SECRET. Anyone with it can sign
// rules that will execute in your CI. Store in a password manager / KMS,
// never in source control or shell history. Use --rotate to retire keys.

import { keygen, signRulePack, verifyRulePack, loadTrustedKeys } from '../src/posture/rule-pack-signing.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const cmd = process.argv[2];
const args = process.argv.slice(3);

function die(msg, code = 1) {
  process.stderr.write(msg + '\n');
  process.exit(code);
}

function pickArg(flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : null;
}

if (cmd === 'keygen') {
  // Premortem 3R3.2 / 3R-5: keygen output contains a PRIVATE KEY. Three
  // safety rails:
  //   1. If --out <path> is supplied AND the path resolves under the project's
  //      .agentic-security/ directory, REFUSE. That directory tends to be
  //      cloud-synced / git-checked / editor-recent. The right place for
  //      private keys is outside source control.
  //   2. If stdout is not a TTY (redirected to a file or pipe) AND no --out
  //      was specified, WARN that the operator is about to write a private
  //      key somewhere we can't see; suggest --out so we can validate.
  //   3. Operators who really mean it can pass --i-understand-private-keys
  //      to silence the warnings.
  const outArg = pickArg('--out');
  const understandFlag = args.includes('--i-understand-private-keys');
  if (outArg) {
    const projectAgenticDir = path.resolve(process.cwd(), '.agentic-security') + path.sep;
    const absOut = path.resolve(outArg);
    if (absOut.startsWith(projectAgenticDir)) {
      die(
        `Refusing to write a private key into ${absOut}.\n` +
        `  .agentic-security/ is typically git-tracked, cloud-synced, or editor-indexed.\n` +
        `  Choose a location OUTSIDE the project tree (e.g. ~/.config/agentic-security/keys/).\n` +
        `  Override with --i-understand-private-keys if you really mean it.`,
        2);
    }
  } else if (!process.stdout.isTTY && !understandFlag) {
    process.stderr.write(
      'agentic-security-rule: WARNING — stdout is being redirected, but no --out was specified.\n' +
      '  This command emits a PRIVATE KEY. We cannot validate where it ends up.\n' +
      '  Re-run with --out <path-outside-project> so we can check the destination,\n' +
      '  or with --i-understand-private-keys to silence this warning.\n');
    process.exit(3);
  }
  const kp = keygen();
  const out = {
    note: 'STORE THE privateKey SECURELY. Do not commit it to source control. Anyone with this key can sign rules that execute in your CI.',
    id: `key-${new Date().toISOString().slice(0, 10)}-${Math.random().toString(36).slice(2, 6)}`,
    alg: 'ed25519',
    issuedAt: new Date().toISOString(),
    publicKey:  kp.publicKey,
    privateKey: kp.privateKey,
  };
  const payload = JSON.stringify(out, null, 2) + '\n';
  if (outArg) {
    fs.writeFileSync(outArg, payload, { mode: 0o600 });
    process.stderr.write(`\nagentic-security-rule: keypair written to ${outArg} (mode 0600).\n`);
  } else {
    process.stdout.write(payload);
  }
  process.stderr.write('  · Add publicKey to .agentic-security/trusted-keys.json (this IS git-trackable)\n');
  process.stderr.write('  · Store privateKey in a password manager / KMS\n');
  process.stderr.write('  · Set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1 so the scanner trusts project-local keys\n');
  process.exit(0);
}

if (cmd === 'sign') {
  const target = args.find(a => !a.startsWith('--'));
  if (!target) die('Usage: agentic-security-rule sign <rule-yml> [--key <base64>]');
  if (!fs.existsSync(target)) die(`File not found: ${target}`);
  const key = pickArg('--key') || process.env.AGENTIC_SECURITY_PRIVATE_KEY;
  if (!key) die('No private key. Set AGENTIC_SECURITY_PRIVATE_KEY or pass --key <base64>.');
  try {
    signRulePack(target, key);
    process.stdout.write(`Signed: ${target}.sig\n`);
    process.exit(0);
  } catch (e) {
    die(`Sign failed: ${e.message}`);
  }
}

if (cmd === 'verify') {
  const target = args.find(a => !a.startsWith('--'));
  if (!target) die('Usage: agentic-security-rule verify <rule-yml>');
  if (!fs.existsSync(target)) die(`File not found: ${target}`);
  const scanRoot = path.resolve('.');
  const keys = loadTrustedKeys(scanRoot);
  if (keys.length === 0) {
    process.stderr.write('agentic-security-rule: no trusted keys configured.\n');
    process.stderr.write('  Add keys to .agentic-security/trusted-keys.json and set AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1.\n');
    process.exit(2);
  }
  const r = verifyRulePack(target, keys);
  if (r.ok) {
    process.stdout.write(`OK — signed by ${r.keyId}\n`);
    process.exit(0);
  } else {
    process.stderr.write(`FAILED: ${r.reason}${r.keyId ? ` (key ${r.keyId})` : ''}\n`);
    process.exit(1);
  }
}

die(`Usage: agentic-security-rule <keygen | sign <rule.yml> | verify <rule.yml>>`);
