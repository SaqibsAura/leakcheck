#!/usr/bin/env node
import { scanPath } from './scan.ts';

const target = process.argv[2] ?? '.';
const findings = scanPath(target);

if (findings.length === 0) {
  console.log(`leakcheck: no secrets found in ${target}`);
  process.exit(0);
}

for (const f of findings) {
  const where = f.line > 0 ? `${f.file}:${f.line}` : f.file;
  console.log(`${where}  [${f.rule}]  ${f.preview}`);
}
console.log(`\nleakcheck: ${findings.length} possible secret(s) found. Review before pushing.`);
process.exit(1);
