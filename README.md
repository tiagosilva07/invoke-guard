# Zyrax Guard

[![CI](https://github.com/tiagosilva07/zyrax-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tiagosilva07/zyrax-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tiagosilva07/zyrax-guard)](https://goreportcard.com/report/github.com/tiagosilva07/zyrax-guard)

**Check a dependency before you install it.** Zyrax Guard vets packages for
typosquats, known-malicious names, hallucinated package names, and supply-chain
anomalies — in milliseconds, before the install runs. **Works with npm, PyPI, and
crates.io** (one ecosystem-agnostic engine).

```
$ zyrax-guard check reqeust
✗ reqeust@latest — BLOCK
  - looks like a typo of "request" (far more popular); this name has only 3 weekly downloads
  did you mean: request
  to override:  zyrax-guard allow reqeust
```

Works locally, in CI, and as a gate for AI coding agents. No account required. Nothing
phones home except the public package name you are querying.

---

## Install

### `go install` (Go 1.23+)

```bash
go install github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest
```

> `@latest` resolves once the first release is tagged. Before then, pin a branch
> (`@main`) or build from source below.

### Build from source

```bash
git clone https://github.com/tiagosilva07/zyrax-guard
cd zyrax-guard
go build -o zyrax-guard ./cmd/zyrax-guard
```

### Signed release binary

Download from [Releases](https://github.com/tiagosilva07/zyrax-guard/releases).
Every release ships:

- Pre-built binaries for linux/darwin/windows × amd64/arm64
- `checksums.txt` (SHA-256)
- SLSA L3 build provenance (`.cosign.bundle` per artifact)
- SBOM (`zyrax-guard.spdx.json`)

Verify a binary:

```bash
cosign verify-blob \
  --bundle zyrax-guard-linux-amd64.cosign.bundle \
  zyrax-guard-linux-amd64
```

---

## Quickstart

### Check a single package

```bash
$ zyrax-guard check express
✓ express@latest — SAFE
```

```bash
$ zyrax-guard check reqeust
✗ reqeust@latest — BLOCK
  - looks like a typo of "request" (far more popular); this name has only 3 weekly downloads
  did you mean: request
  to override:  zyrax-guard allow reqeust
```

### Check-then-install

```bash
$ zyrax-guard install lodash axios
✓ lodash@latest — SAFE
✓ axios@latest — SAFE
# runs: npm install lodash axios
```

```bash
$ zyrax-guard install reqeust
✗ reqeust@latest — BLOCK
  - looks like a typo of "request"
blocked — not installing. Override with: zyrax-guard allow <name>
```

### Allow a package (add to local policy)

```bash
$ zyrax-guard allow my-internal-pkg
allowed "my-internal-pkg" (recorded in .zyrax/policy.json)
```

Commit `.zyrax/policy.json` — it is the reviewable allowlist for your project.

### Scan a PR's lockfile diff

```bash
$ zyrax-guard scan --base /tmp/base-lock.json --head package-lock.json --sarif
```

Emits SARIF 2.1.0 to stdout. Exit code 0 if no BLOCK; non-zero otherwise.
Add `--strict` to treat WARN as failure.

---

## Ecosystems

Guard supports **npm, PyPI, and crates.io**. Pick one with `--ecosystem` (default `npm`):

```bash
zyrax-guard check --ecosystem pypi requests
zyrax-guard check --ecosystem crates serde
zyrax-guard install --ecosystem pypi flask        # vets, then runs pip install
zyrax-guard install --ecosystem crates serde      # vets, then runs cargo add
```

The shell hook and PR gate work per ecosystem too:

```bash
eval "$(zyrax-guard init bash pip)"      # gate pip install
eval "$(zyrax-guard init bash cargo)"    # gate cargo add
zyrax-guard scan --ecosystem crates      # PR gate over Cargo.lock
zyrax-guard scan --ecosystem pypi        # PR gate over poetry.lock / requirements.txt
```

The MCP `check_package` tool takes an `ecosystem` argument (`npm`/`pypi`/`crates`).

---

## How the checks work

Zyrax Guard runs four checks against public registry metadata — no local execution,
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

## Deep check (`--deep`)

By default Guard checks are metadata-only (milliseconds). Add `--deep` to also download the
package's distribution artifact and **statically analyze the code it runs at install/build
time** — npm `preinstall`/`install`/`postinstall` scripts, PyPI `setup.py`, crates `build.rs`:

```bash
zyrax-guard check --deep --ecosystem npm some-pkg
zyrax-guard scan --deep --ecosystem pypi          # PR gate, deep
```

It flags red flags — network calls, process spawning, base64/obfuscated `eval`, and
sensitive-file/env access — and **BLOCKs** on the dangerous combinations (e.g. "download a
script and run it"). It runs **no code** (purely static) and is **best-effort**: if the
artifact can't be fetched, you get an informational note, never a false block. Agents can pass
`deep: true` to the `check_package` MCP tool.

`scan --deep` downloads and inspects each **added** dependency in turn, so its cost scales with
the size of the diff. The whole pass is bounded by an overall time budget (3 minutes); on a very
large diff any packages past the budget fall back to a metadata-only check (you'll see a note on
stderr).

Zero added dependencies — the extractor uses stdlib `archive/tar` + `compress/gzip` only.

---

## The three verdicts

| Verdict | Meaning | Default exit code |
|---|---|---|
| **SAFE** | No signals worth noting | `0` |
| **WARN** | Suspicious — review before proceeding | `0` (use `--strict` to make it `1`) |
| **BLOCK** | Strong indicator of malicious or hallucinated package | `1` |

Policy overlays everything: `zyrax-guard allow <name>` forces SAFE regardless of signals;
a `.zyrax/policy.json` deny entry forces BLOCK.

---

## Using with AI coding agents

AI agents sometimes hallucinate package names. Attackers pre-register those names with
malware. Guard breaks that attack chain.

**Native agent integration (MCP):** register Guard as a tool your agent can call, so it
checks a package *before* it ever runs an install command:

```bash
claude mcp add zyrax-guard -- zyrax-guard mcp
```

The agent gets a `check_package` tool that returns SAFE / WARN / BLOCK with reasons.
(Cursor / Windsurf: add an equivalent `mcpServers` entry running `zyrax-guard mcp`.)

**Transparent shell hook:** gate `npm install` / `pip install` / `cargo add` automatically — add to your shell rc:

```bash
# ~/.bashrc or ~/.zshrc
eval "$(zyrax-guard init bash)"          # npm (default)
eval "$(zyrax-guard init bash pip)"      # pip
eval "$(zyrax-guard init bash cargo)"    # cargo
```
```powershell
# PowerShell $PROFILE
Invoke-Expression (zyrax-guard init powershell | Out-String)
```

The hook checks each newly added package and blocks before the real installer runs;
non-install commands pass through untouched.

**Or route installs manually:** `zyrax-guard install <pkg>` checks, then installs only if
nothing is blocked.

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
      - run: go install github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest
      - name: Guard new dependencies
        run: |
          git show "origin/${{ github.base_ref }}:package-lock.json" > /tmp/base-lock.json 2>/dev/null || echo '{"packages":{}}' > /tmp/base-lock.json
          zyrax-guard scan --base /tmp/base-lock.json --head package-lock.json --strict --sarif > guard.sarif
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
zyrax-guard scan --base "$BASE_LOCK" --head package-lock.json --sarif --strict > guard.sarif
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

## Free & open source

Zyrax Guard is **MIT-licensed and free** — every check, the PR gate, the MCP server, the
shell hook, and the JSON/SARIF output. Read the code and verify the binary yourself.

---

## Roadmap

| Phase | Item |
|---|---|
| **v1** | npm CLI + PR gate + JSON/SARIF + self-hardening |
| **v1.1** | MCP server (`check_package`) + shell-hook (`zyrax-guard init`) — shipped |
| **v1.2** | PyPI + crates.io across check/install/hook/MCP/scan — shipped |
| **v1.3** (now) | Deep check (`--deep`): static install/build-script analysis — shipped |

The roadmap items drop in via the existing `Ecosystem`, `ThreatIntel`, `Policy`, and
`Reporter` seams — no re-architecting required.

---

## License

MIT — see [LICENSE](LICENSE).
