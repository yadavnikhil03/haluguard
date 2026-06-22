<p align="center">
  <img src="./assets/banner.png" alt="HaluGuard Banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/yadavnikhil03/haluguard/actions"><img alt="Build Status" src="https://img.shields.io/github/actions/workflow/status/yadavnikhil03/haluguard/haluguard.yml?style=flat-square"></a>
  <img alt="license" src="https://img.shields.io/badge/license-Apache%202.0-3DA639?style=flat-square">
  <img alt="node" src="https://img.shields.io/badge/node-%3E%3D18-cc3366?style=flat-square">
  <img alt="tests" src="https://img.shields.io/badge/tests-66%20passing-5849be?style=flat-square">
  <img alt="config" src="https://img.shields.io/badge/zero%20config-22c55e?style=flat-square">
</p>

<p align="center">
  <strong>Local-first.</strong> No cloud. No API keys. No telemetry.
  <br>
  Detects <strong>hallucinated APIs</strong>, <strong>leaked secrets</strong>, <strong>stubs</strong> & more in AI-generated code.
</p>

---

## The problem

AI coding assistants (Copilot, Cursor, Cline, Aider, Claude Code) write code that **looks correct but isn't**:

```typescript
import * as crypto from "node:crypto";
const id = crypto.randomUUIDv4();   // ❌ TypeError — there's no randomUUIDv4
JSON.deserialize(body);              // ❌ TypeError — it's JSON.parse
```

These bugs pass type-checking, look plausible in review, and **crash in production**. Linters can't catch them — they only know about patterns, not real API surfaces.

> [Stack Overflow's 2026 report](https://stackoverflow.blog/2026/02/18/closing-the-developer-ai-trust-gap/) calls this the **"AI trust gap"** — the #1 unsolved problem in AI-assisted dev.

## The solution

HaluGuard cross-references AI-written code against **real API surfaces** and catches the failure modes unique to AI output — in your terminal, on every PR, in CI.

```
🛡️  HaluGuard found 7 issues

src/auth.ts
  🔴 HIGH  6  AWS Access Key ID
     → AKIA**************LE
  🟡 MED  10  Possibly invented method: crypto.randomUUIDv4
     `crypto` does not export `randomUUIDv4`. Did you mean `crypto.randomUUID`?
     → const id = crypto.randomUUIDv4();
  🟡 MED  14  Stubbed implementation throws at runtime
     → throw new Error("not implemented");

─────────────────────────────────────
1 high  5 medium  1 info
Scanned 1 files, 19 added lines in 4ms
```

## Install & Run

You can run HaluGuard directly from GitHub without needing to install anything:

```sh
# Run once via NPX (fetches directly from this repo)
npx github:yadavnikhil03/haluguard src/auth.ts
```

If you prefer to install it globally on your machine:

```sh
# Clone and install globally
git clone https://github.com/yadavnikhil03/haluguard.git
cd haluguard
npm install -g .

# Now you can use it anywhere
haluguard src/auth.ts
```

## Quick start

```sh
# Scan files
haluguard src/auth.ts src/utils.ts

# Scan what changed vs main (most common CI use)
git diff main...HEAD | haluguard --stdin

# Only check secrets
haluguard src/ --detectors secrets

# SARIF for GitHub Security tab
git diff origin/main | haluguard --stdin --format sarif > results.sarif

# Fail CI on HIGH+ findings
haluguard --stdin --fail-on high < diff.patch
```

## Detectors

| Detector | Severity | Catches |
|----------|----------|---------|
| **`hallucinated_apis`** | 🟡 MED | Invented methods (`crypto.randomUUIDv4`, `os.hostnameSync`, `JSON.deserialize`) with **"did you mean"** suggestions |
| **`secrets`** | 🔴 HIGH/CRIT | AWS, GitHub, OpenAI, Anthropic, Stripe, Slack keys, JWTs, private keys, + generic high-entropy tokens |
| **`stubs`** | 🟡 MED / ℹ️ INFO | `throw new Error("not implemented")`, `NotImplementedError`, bare `pass`, `TODO`/`FIXME`, `dummy_value` returns |

**Languages:** TypeScript, JavaScript, TSX, JSX, Python, Go, Rust, Java, C#, PHP.

## GitHub Action

Drop into `.github/workflows/haluguard.yml`:

```yaml
name: HaluGuard
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: git diff origin/$GITHUB_BASE_REF | npx haluguard --stdin --fail-on high
```

**SARIF mode** (inline annotations in the Security tab):

```yaml
      - run: git diff origin/$GITHUB_BASE_REF | npx haluguard --stdin --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Comparison

| Feature | **HaluGuard** | Semgrep | Gitleaks | VulnHawk |
|---------|:---:|:---:|:---:|:---:|
| Hallucinated API detection | ✅ | ❌ | ❌ | ❌ |
| "Did you mean" suggestions | ✅ | ❌ | ❌ | ❌ |
| Leaked secrets | ✅ | ❌ | ✅ | ✅ |
| Stub / TODO detection | ✅ | ❌ | ❌ | ❌ |
| Built for AI output | ✅ | ❌ | ❌ | ⚠️ |
| Scans added lines only (not history) | ✅ | — | ❌ | — |
| Local-first, no cloud | ✅ | ✅ | ✅ | ❌ |
| No API key required | ✅ | ❌ | ✅ | ❌ |
| Open source (Apache 2.0) | ✅ | ✅ | ✅ | ❌ |
| SARIF output | ✅ | ✅ | ❌ | ✅ |
| GitHub Action | ✅ | ✅ | ✅ | ✅ |

**HaluGuard complements, not replaces, SAST tools.** Use Semgrep for vulns, Gitleaks for secret history, HaluGuard for AI-specific issues.

## CLI options

```
--format <pretty|json|sarif>   Output format (default: pretty)
--min-severity <level>         info | low | medium | high | critical
--detectors <id,id,...>        Only run these detectors
--ignore <glob>                Ignore paths (repeatable)
--fail-on <level>              Exit non-zero at/above severity (default: high)
--stdin                        Read diff from stdin
--config <path>                Path to .haluguard.yml config file
--init-hook                    Install a pre-commit git hook
-h, --help                     Show help
-v, --version                  Print version
```

## Configuration

Create a `.haluguard.yml` in your project root:

```yaml
detectors:
  - secrets
  - hallucinated_apis
  - stubs

min_severity: medium

ignore:
  - "vendor/**"
  - "*.test.ts"

fail_on: high
```

CLI flags always take precedence over config file values.

## Inline Ignores

Suppress specific findings with inline directives:

```typescript
const key = "AKIAIOSFODNN7EXAMPLE"; // haluguard: ignore

// haluguard: ignore secret:aws_access_key_id
const key2 = "AKIAIOSFODNN7EXAMPLE";

// haluguard: ignore secrets
const key3 = "AKIAIOSFODNN7EXAMPLE";
```

Works on the same line or the line above. Supports Python `#` comments too.

## Pre-commit Hook

```sh
# Auto-install:
haluguard --init-hook

# Or manually copy scripts/pre-commit-hook.sh to .git/hooks/pre-commit
```

## Programmatic API

```typescript
import { runScan, parseDiff, renderReport } from "haluguard";

const diff = await getPullRequestDiff();
const files = parseDiff(diff);
const report = await runScan(files, { minSeverity: "medium" });

console.log(renderReport(report));
// → pretty terminal output
// or report.findings[] for custom handling
```

## Privacy & security

- **Never sends your code anywhere** — 100% local analysis
- **No API keys, no accounts, no cloud calls**
- **Zero telemetry**
- **Apache 2.0** — free for any use, including commercial
- Secrets are **redacted in all output** so reports are safe to share

## Performance

- Scans **~5,000 lines/second** on a laptop
- **Zero external runtime dependencies** (only dev deps for build)
- Sub-100ms startup
- Runs in CI as a single `npx` call

## Roadmap

- [x] `.haluguard.yml` config file (rules, ignore, baselines)
- [x] Inline `// haluguard: ignore` directives
- [x] Pre-commit hook
- [x] Go, Rust, Java, C#, PHP, Python support for hallucinated APIs
- [ ] `malicious_packages` detector (typosquat / hijack detection via OpenSSF)
- [ ] `ai_logic` LLM-as-judge detector (optional, BYO key)
- [ ] VS Code extension

## Contributing

PRs welcome. HaluGuard is intentionally small and readable — the whole engine is under 1,500 lines.

```sh
git clone https://github.com/yadavnikhil03/haluguard.git
cd haluguard
npm install
npm test        # 58 tests, <2s
npm run build   # produces dist/
```

To add a detector, create a file in `src/detectors/` implementing the `Detector` interface and register it in `src/core/engine.ts`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache License 2.0](LICENSE) © 2026
