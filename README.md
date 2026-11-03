# leakcheck

A small, zero-dependency secret scanner. Run it before you push.

```text
$ node src/cli.ts .
config.js:1  [github-token]  ghp_************
.env  [env-file]  (.env files should not be committed)

leakcheck: 2 possible secret(s) found. Review before pushing.
```

I built this because I scan every repo for secrets before I make anything public. I wanted something
I fully understand: about 100 lines, no dependencies, and it never prints the full secret.

## What it finds

| Rule | Catches |
| :--- | :--- |
| `github-token` | `ghp_`, `gho_`, `ghs_`… and fine-grained `github_pat_` tokens |
| `aws-access-key` | `AKIA…` / `ASIA…` key IDs |
| `google-api-key` | `AIza…` keys |
| `openai-key` / `anthropic-key` | `sk-…` / `sk-ant-…` keys |
| `slack-token` | `xox…` tokens |
| `stripe-live-key` | `sk_live_` / `rk_live_` keys |
| `private-key` | `-----BEGIN … PRIVATE KEY-----` blocks |
| `generic-secret` | `password = "…"`, `api_key: '…'` and similar hard-coded values |
| `env-file` | any committed `.env` / `.env.local` (but not `.env.example`) |

It skips `.git`, `node_modules`, `dist`, `build`, binary files and files over 1 MB.
Add `leakcheck:allow` to a line to skip a documented example value.

## Usage

Requires Node.js 23.6+.

```bash
git clone https://github.com/SaqibsAura/leakcheck
cd leakcheck
node src/cli.ts /path/to/your/repo
```

Exit code is `0` when clean and `1` when something is found, so it works as a pre-push hook or a CI step.

## Tests

`npm test` runs 7 tests covering every token type, line numbers, redaction, allow-listing,
directory walking and the CLI exit codes. Test secrets are built at runtime, so the repo scans clean itself.

## Honest limits

This is a pattern scanner, not a replacement for tools like gitleaks or GitHub secret scanning:

- It only scans the files as they are now, **not git history**.
- No entropy analysis, so unusual secret formats can slip through.
- Pattern rules can produce false positives. Always review the results.

## License

MIT © Sheikh Mohammed Saqib
