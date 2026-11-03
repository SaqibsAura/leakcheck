import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanText, scanPath, redact } from '../src/scan.ts';

// Fake values are built at runtime so this file never contains a real-looking secret itself.
const fakeGithub = 'ghp_' + 'A'.repeat(36);
const fakeAws = 'AKIA' + 'B'.repeat(16);
const fakeGoogle = 'AIza' + 'c'.repeat(35);
const fakeOpenAI = 'sk-proj-' + 'd'.repeat(40);

test('detects common token formats', () => {
  const text = [`token = ${fakeGithub}`, `aws ${fakeAws}`, `key ${fakeGoogle}`, `openai ${fakeOpenAI}`].join('\n');
  const rules = scanText(text).map((f) => f.rule);
  assert.deepEqual(rules, ['github-token', 'aws-access-key', 'google-api-key', 'openai-key']);
});

test('detects private key blocks and hard-coded passwords', () => {
  const pk = '-----BEGIN ' + 'PRIVATE KEY-----';
  const pw = 'const password = "' + 'hunter2hunter2' + '"';
  assert.deepEqual(scanText(`${pk}\n${pw}`).map((f) => f.rule), ['private-key', 'generic-secret']);
});

test('reports correct line numbers', () => {
  const f = scanText(`line one\nline two\n${fakeAws}`);
  assert.equal(f[0].line, 3);
});

test('never prints the full secret', () => {
  const [f] = scanText(fakeGithub);
  assert.ok(!f.preview.includes(fakeGithub));
  assert.ok(f.preview.startsWith('ghp_'));
  assert.equal(redact('abc'), '****');
});

test('ignores clean text, env references and allow-listed lines', () => {
  assert.deepEqual(scanText('const key = process.env.API_KEY;\nconst n = 42;'), []);
  assert.deepEqual(scanText(`${fakeAws} // leakcheck:allow`), []);
});

test('scans directories, flags .env files, skips node_modules and binaries', () => {
  const dir = mkdtempSync(join(tmpdir(), 'leakcheck-'));
  try {
    writeFileSync(join(dir, 'clean.ts'), 'export const x = 1;\n');
    writeFileSync(join(dir, 'config.js'), `module.exports = { t: "${fakeGithub}" };\n`);
    writeFileSync(join(dir, '.env'), 'X=1\n');
    writeFileSync(join(dir, '.env.example'), 'X=\n');
    writeFileSync(join(dir, 'blob.bin'), Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from(fakeAws)]));
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'dep.js'), fakeAws);
    const rules = scanPath(dir).map((f) => `${f.file}:${f.rule}`).sort();
    assert.deepEqual(rules, ['.env:env-file', 'config.js:github-token']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI exits 1 on findings and 0 when clean', () => {
  const dir = mkdtempSync(join(tmpdir(), 'leakcheck-cli-'));
  try {
    writeFileSync(join(dir, 'a.txt'), 'nothing here\n');
    const cli = join(import.meta.dirname, '..', 'src', 'cli.ts');
    assert.equal(spawnSync(process.execPath, [cli, dir]).status, 0);
    writeFileSync(join(dir, 'b.txt'), fakeAws);
    const dirty = spawnSync(process.execPath, [cli, dir], { encoding: 'utf8' });
    assert.equal(dirty.status, 1);
    assert.ok(!dirty.stdout.includes(fakeAws));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
