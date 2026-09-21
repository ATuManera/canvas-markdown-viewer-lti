/**
 * Regenerates THIRD_PARTY_NOTICES.md from the installed runtime dependency tree.
 *
 * Runtime only: development dependencies are not distributed, so listing them would
 * misrepresent what the container actually contains.
 */
import { execSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const tree = JSON.parse(
  execSync('npm ls --all --json --omit=dev', { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
);

const seen = new Map();
(function walk(node) {
  for (const [name, info] of Object.entries(node.dependencies ?? {})) {
    if (info.version) seen.set(`${name}@${info.version}`, info);
    walk(info);
  }
})(tree);

const rows = [];
const byLicence = new Map();

for (const entry of [...seen.keys()].sort()) {
  const at = entry.lastIndexOf('@');
  const name = entry.slice(0, at);
  const version = entry.slice(at + 1);

  let licence = 'UNKNOWN';
  let repository = '';
  try {
    const pkg = JSON.parse(readFileSync(join('node_modules', name, 'package.json'), 'utf8'));
    licence =
      typeof pkg.license === 'string'
        ? pkg.license
        : (pkg.license?.type ??
          (Array.isArray(pkg.licenses) ? pkg.licenses.map((l) => l.type).join(' OR ') : 'UNKNOWN'));
    const raw = typeof pkg.repository === 'string' ? pkg.repository : (pkg.repository?.url ?? '');
    repository = raw
      .replace(/^git\+/, '')
      .replace(/\.git$/, '')
      .replace(/^git:\/\//, 'https://');
  } catch {
    // A package without a readable manifest is reported as UNKNOWN rather than skipped.
  }

  rows.push({ name, version, licence, repository });
  byLicence.set(licence, (byLicence.get(licence) ?? 0) + 1);
}

const forbidden = rows.filter((r) => /GPL|AGPL|LGPL|SSPL|BUSL/i.test(r.licence));
if (forbidden.length > 0) {
  process.stderr.write(
    `Copyleft or source-available licence found:\n${forbidden.map((r) => `  ${r.name}@${r.version}: ${r.licence}`).join('\n')}\n`,
  );
  process.exit(1);
}

const unknown = rows.filter((r) => r.licence === 'UNKNOWN');
if (unknown.length > 0) {
  process.stderr.write(
    `Package with no declared licence:\n${unknown.map((r) => `  ${r.name}@${r.version}`).join('\n')}\n`,
  );
  process.exit(1);
}

process.stdout.write(`${rows.length} runtime packages, all with a declared licence.\n`);
for (const [licence, count] of [...byLicence.entries()].sort((a, b) => b[1] - a[1])) {
  process.stdout.write(`  ${licence}: ${count}\n`);
}

writeFileSync(
  '/tmp/third-party-table.md',
  `| Licence | Packages |\n|---|---|\n${[...byLicence.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([l, c]) => `| ${l} | ${c} |`)
    .join('\n')}\n\n| Package | Version | Licence |\n|---|---|---|\n${rows
    .map(
      (r) =>
        `| ${r.repository ? `[${r.name}](${r.repository})` : r.name} | ${r.version} | ${r.licence} |`,
    )
    .join('\n')}\n`,
);
