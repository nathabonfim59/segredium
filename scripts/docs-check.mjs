#!/usr/bin/env node
/**
 * Fails when docs/api-reference/ does not match what the Go source generates.
 *
 * It fingerprints the committed pages, regenerates them with scripts/docs-api.mjs, and compares.
 * A changed, added or removed page all count as stale, including pages git does not track yet.
 * On failure the regenerated pages stay on disk, so you can commit them.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const apiDir = join(root, 'docs', 'api-reference');

function snapshot() {
  const files = new Map();
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) walk(path);
      else files.set(relative(apiDir, path).split('\\').join('/'), createHash('sha256').update(readFileSync(path)).digest('hex'));
    }
  };
  if (existsSync(apiDir)) walk(apiDir);
  return files;
}

const before = snapshot();
execFileSync('node', [join(root, 'scripts', 'docs-api.mjs')], { cwd: root, stdio: 'inherit' });
const after = snapshot();

const stale = [];
for (const [file, hash] of after) {
  if (!before.has(file)) stale.push(`missing: ${file}`);
  else if (before.get(file) !== hash) stale.push(`changed: ${file}`);
}
for (const file of before.keys()) if (!after.has(file)) stale.push(`obsolete: ${file}`);

if (stale.length) {
  console.error(`docs/api-reference is out of date (${stale.length} pages):`);
  for (const line of stale) console.error(`  ${line}`);
  console.error("Run 'npm run docs:api' and commit docs/api-reference.");
  process.exit(1);
}
console.log(`docs/api-reference is up to date (${after.size} pages).`);
