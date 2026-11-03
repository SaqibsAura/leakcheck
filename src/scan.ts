/**
 * leakcheck — find secrets in files before they reach a public repo.
 * Pattern rules plus a .env check. Matches are always redacted in output.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, basename } from 'node:path';

export interface Rule {
  id: string;
  description: string;
  pattern: RegExp;
}

export interface Finding {
  file: string;
  line: number;
  rule: string;
  preview: string;
}

export const RULES: Rule[] = [
  { id: 'github-token', description: 'GitHub token', pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/ },
  { id: 'aws-access-key', description: 'AWS access key ID', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { id: 'google-api-key', description: 'Google API key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { id: 'openai-key', description: 'OpenAI API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { id: 'anthropic-key', description: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { id: 'slack-token', description: 'Slack token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { id: 'stripe-live-key', description: 'Stripe live key', pattern: /\b[sr]k_live_[A-Za-z0-9]{20,}\b/ },
  { id: 'private-key', description: 'Private key block', pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/ },
  {
    id: 'generic-secret',
    description: 'Hard-coded secret assignment',
    pattern: /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"][^'"\s]{8,}['"]/i
  }
];

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next']);
const MAX_BYTES = 1_000_000;

/** Keep the first 4 characters so a finding can be recognised, hide the rest. */
export function redact(secret: string): string {
  return secret.length <= 4 ? '****' : secret.slice(0, 4) + '*'.repeat(Math.min(secret.length - 4, 12));
}

/** A line marked with `leakcheck:allow` is skipped (for documented example values). */
export function scanText(text: string, file = '<text>'): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((content, i) => {
    if (content.includes('leakcheck:allow')) return;
    for (const rule of RULES) {
      const m = rule.pattern.exec(content);
      if (m) findings.push({ file, line: i + 1, rule: rule.id, preview: redact(m[0]) });
    }
  });
  return findings;
}

function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8000).includes(0);
}

function isEnvFile(name: string): boolean {
  return name === '.env' || (name.startsWith('.env.') && !/\.(example|sample|template)$/.test(name));
}

export function scanPath(root: string): Finding[] {
  const findings: Finding[] = [];
  const walk = (p: string) => {
    const st = statSync(p);
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(basename(p))) return;
      for (const entry of readdirSync(p)) walk(join(p, entry));
      return;
    }
    if (!st.isFile()) return;
    const rel = relative(root, p) || basename(p);
    if (isEnvFile(basename(p))) {
      findings.push({ file: rel, line: 0, rule: 'env-file', preview: '(.env files should not be committed)' });
    }
    if (st.size > MAX_BYTES) return;
    const buf = readFileSync(p);
    if (isBinary(buf)) return;
    findings.push(...scanText(buf.toString('utf8'), rel));
  };
  walk(root);
  return findings;
}
