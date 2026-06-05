# Invoke Guard

[![CI](https://github.com/tiagosilva07/invoke-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tiagosilva07/invoke-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tiagosilva07/invoke-guard)](https://goreportcard.com/report/github.com/tiagosilva07/invoke-guard)

**Check a dependency before you install it.** Invoke Guard vets packages for
typosquats, known-malicious names, hallucinated package names, and supply-chain
anomalies — in milliseconds, before the install runs. **npm today; PyPI and crates
on the roadmap** (the engine is ecosystem-agnostic by design).

```
$ invoke-guard check reqeust
✗ reqeust@latest — BLOCK
  - looks like a typo of "request" (far more popular); this name has only 3 weekly downloads
  did you mean: request
  to override:  invoke-guard allow reqeust
```

Works locally, in CI, and as a gate for AI coding agents. No account required. Nothing
phones home except the public package name you are querying.

---

## Install

### `go install` (Go 1.23+)

```bash
go install github.com/tiagosilva07/invoke-guard/cmd/invoke-guard@latest
```

> `@latest` resolves once the first release is tagged. Before then, pin a branch
> (`@main`) or build from source below.

### Build from source

```bash
git clone https://github.com/tiagosilva07/invoke-guard
cd invoke-guard
go build -o invoke-guard ./cmd/invoke-guard
```

### Signed release binary

Download from [Releases](https://github.com/tiagosilva07/invoke-guard/releases).
Every release ships:

- Pre-built binaries for linux/darwin/windows × amd64/arm64
- `checksums.txt` (SHA-256)
- SLSA L3 build provenance (`.cosign.bundle` per artifact)
- SBOM (`invoke-guard.spdx.json`)

Verify a binary:

```bash
cosign verify-blob \
  --bundle invoke-guard-linux-amd64.cosign.bundle \
  invoke-guard-linux-amd64
```

---

## Quickstart

### Check a single package

```bash
$ invoke-guard check express
✓ express@latest — SAFE
```

```bash
$ invoke-guard check reqeust
✗ reqeust@latest — BLOCK
  - looks like a typo of "request" (far more popular); this name has only 3 weekly downloads
  did you mean: request
  to override:  invoke-guard allow reqeust
```

### Check-then-install

```bash
$ invoke-guard install lodash axios
✓ lodash@latest — SAFE
✓ axios@latest — SAFE
# runs: npm install lodash axios
```

```bash
$ invoke-guard install reqeust
✗ reqeust@latest — BLOCK
  - looks like a typo of "request"
blocked — not installing. Override with: invoke-guard allow <name>
```

### Allow a package (add to local policy)

```bash
$ invoke-guard allow my-internal-pkg
allowed "my-internal-pkg" (recorded in .invoke/policy.json)
```

Commit `.invoke/policy.json` — it is the reviewable allowlist for your project.

### Scan a PR's lockfile diff

```bash
$ invoke-guard scan --base /tmp/base-lock.json --head package-lock.json --sarif
```

Emits SARIF 2.1.0 to stdout. Exit code 0 if no BLOCK; non-zero otherwise.
Add `--strict` to treat WARN as failure.

---

## How the checks work

Invoke Guard runs four checks against public registry metadata — no local execution,
no installs, no sandboxing required:

| Check | Verdict trigger |
|---|---|
| **Existence** | Package not found on the registry → **BLOCK** (hallucinated or trap name) |
| **Typosquat** | Name is 1 edit away from a much-more-popular package AND itself has near-zero downloads → **BLOCK** with a "did you mean" suggestion. Weaker similarity → **WARN**. |
| **Known-bad** | OSV advisory or bundled denylist match → malware / high-severity → **BLOCK**; low-severity → **WARN** |
| **Age & popularity** | Published < 30 days AND < 50 weekly downloads → **WARN** (suspicious, not conclusive alone) |

PR-gate (`scan`) additionally runs:

| Check | Trigger |
|---|---|
| **Lockfile integrity** | Existing dependency's resolved URL or integrity hash changed in the lockfile diff → **BLOCK** |
| **Maintainer change** | New version published by a maintainer not seen before → **WARN** |

---

## The three verdicts

| Verdict | Meaning | Default exit code |
|---|---|---|
| **SAFE** | No signals worth noting | `0` |
| **WARN** | Suspicious — review before proceeding | `0` (use `--strict` to make it `1`) |
| **BLOCK** | Strong indicator of malicious or hallucinated package | `1` |

Policy overlays everything: `invoke-guard allow <name>` forces SAFE regardless of signals;
a `.invoke/policy.json` deny entry forces BLOCK.

---

## Using with AI coding agents

AI agents sometimes hallucinate package names. Attackers pre-register those names with
malware. Guard breaks that attack chain.

**Today (v1):** Route agent installs through Guard instead of npm directly:

```bash
# Instead of: npm install <agent-suggested-pkg>
invoke-guard install <agent-suggested-pkg>
```

Guard checks existence (hallucinated names → BLOCK), typosquats, and known-bad records
before any install runs.

**Roadmap (v1.1):** An MCP server (`check_package` tool) lets agents call Guard
natively, and a shell hook auto-intercepts all `npm install` calls transparently via
`invoke-guard init`.

---

## Using in CI

### GitHub Actions (PR gate)

Install the binary, then gate the PR on its lockfile diff against the target branch:

```yaml
# .github/workflows/guard.yml
name: Dependency guard
on: [pull_request]
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-go@v5
        with: { go-version: "1.26" }
      - run: go install github.com/tiagosilva07/invoke-guard/cmd/invoke-guard@latest
      - name: Guard new dependencies
        run: |
          git show "origin/${{ github.base_ref }}:package-lock.json" > /tmp/base-lock.json 2>/dev/null || echo '{"packages":{}}' > /tmp/base-lock.json
          invoke-guard scan --base /tmp/base-lock.json --head package-lock.json --strict --sarif > guard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: guard.sarif }
```

It checks only **newly added or changed** dependencies (fast, no re-flagging the whole
tree), fails the PR on any BLOCK (and WARN under `--strict`), and uploads SARIF to GitHub
Code Scanning. (Inside this repo, the bundled composite action at
`.github/actions/guard` wraps the same `scan` call.)

### Raw CLI in CI

```bash
# In any CI environment that has the binary:
invoke-guard scan --base "$BASE_LOCK" --head package-lock.json --sarif --strict > guard.sarif
```

Upload `guard.sarif` to GitHub Code Scanning:

```yaml
- uses: github/codeql-action/upload-sarif@7fd177fa680c9881b53cdab4d346d32574c9f7f4  # v3
  with:
    sarif_file: guard.sarif
```

---

## Privacy promise

Only the **public package names you query** leave your machine, as read-only lookups
against:

- `registry.npmjs.org` — existence and metadata
- `api.npmjs.org` — download counts
- `api.osv.dev` — known advisories

No telemetry. No account. No secrets. The binary is reproducible (`-trimpath`), and
every release ships SLSA L3 provenance so you can verify the build chain yourself.

---

## OSS promise

Invoke Guard is **MIT-licensed, free forever for individuals and single-repository use.**

The paid tier adds *data and org services*: a curated threat-intelligence feed, org-wide
policy, a dashboard, and native push to the Invoke platform. The basic safety checks,
the PR gate, and the SARIF/JSON output are not paywalled — now or ever.

See `docs/INTEGRATION-INVOKE.md` for how to connect Guard's output to the Invoke
supply-chain platform.

---

## Roadmap

| Phase | Item |
|---|---|
| **v1** (now) | npm CLI + PR gate + JSON/SARIF + self-hardening + integration docs |
| **v1.1** | MCP server (`check_package` tool) + shell-hook auto-intercept (`invoke-guard init`) |
| **v1.2** | PyPI + crates providers |
| **v1.3** | Deep/sandbox behavioral check (opt-in signal) |
| **paid** | Curated threat feed, org policy, dashboard, native platform push |

None of the roadmap items require re-architecting v1 — they drop in via the existing
`Ecosystem`, `ThreatIntel`, `Policy`, and `Reporter` seams.

---

## License

MIT — see [LICENSE](LICENSE).
