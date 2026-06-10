# Zyrax Guard

[![CI](https://github.com/tiagosilva07/zyrax-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tiagosilva07/zyrax-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/tiagosilva07/zyrax-guard)](https://goreportcard.com/report/github.com/tiagosilva07/zyrax-guard)
[![Website](https://img.shields.io/badge/website-zyrax.io-2cc9da)](https://zyrax.io)

**Check a dependency before you install it.** Zyrax Guard vets packages for
typosquats, known-malicious names, hallucinated package names, and supply-chain
anomalies — in milliseconds, before the install runs. **Works with npm, PyPI, and
crates.io** (one ecosystem-agnostic engine).

```
$ zyrax-guard check lodahs
✗ lodahs@0.0.1-security — BLOCK
  - name is similar to "lodash" — double-check you meant this package
  - MAL-2025-25502: Malicious code in lodahs (npm)
  did you mean: lodash
  to override:  zyrax-guard allow lodahs

$ zyrax-guard check lodash
✓ lodash@4.18.1 — SAFE
```

Works locally, in CI, and as a gate for AI coding agents. No account required. Nothing
phones home except the public package name you are querying.

🌐 **Homepage:** [zyrax.io](https://zyrax.io)

---

## Install

### Quick install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/tiagosilva07/zyrax-guard/main/scripts/install.sh | sh
```

Downloads the signed release binary for your OS/arch, verifies its SHA-256 against
the release checksums, and installs it (to `/usr/local/bin`, or `~/.local/bin` if that
is not writable). Pin a version with `VERSION=v0.5.0`, or set `BINDIR` to choose where
it lands. Verifies the cosign signature too when `cosign` is on your PATH.

### `go install` (Go 1.23+)

```bash
go install github.com/tiagosilva07/zyrax-guard/cmd/zyrax-guard@latest
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

### Build from source

```bash
git clone https://github.com/tiagosilva07/zyrax-guard
cd zyrax-guard
go build -o zyrax-guard ./cmd/zyrax-guard
```

---

## Quickstart

### Check a single package

```bash
zyrax-guard check lodash                          # npm (default)
zyrax-guard check requests --ecosystem pypi       # PyPI
zyrax-guard check serde --ecosystem crates        # crates.io
```

### Check-then-install

```bash
zyrax-guard install lodash axios                  # vets, then runs npm install
zyrax-guard install flask --ecosystem pypi        # vets, then runs pip install
zyrax-guard install serde --ecosystem crates      # vets, then runs cargo add
```

### Allow a package (add to local policy)

```bash
zyrax-guard allow my-internal-pkg
# allowed "my-internal-pkg" (recorded in .zyrax/policy.json)
```

Commit `.zyrax/policy.json` — it is the reviewable allowlist for your project.

### Scan a PR's lockfile diff

```bash
zyrax-guard scan --base /tmp/base-lock.json --head package-lock.json --sarif
```

Emits SARIF 2.1.0 to stdout. Exit code 0 if no BLOCK; non-zero otherwise.
Add `--strict` to treat WARN as failure.

---

## GitHub Action

Gate every pull request: Zyrax Guard checks dependencies added in the PR and fails the
check if any is blocked. Add `.github/workflows/zyrax-guard.yml`:

```yaml
name: Zyrax Guard
on: pull_request
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # lets Guard diff against the PR base (added deps only)
      - uses: tiagosilva07/zyrax-guard@v0.6.0
        with:
          ecosystem: npm          # npm | pypi | crates
```

On a pull request it scans only the dependencies added versus the base branch; otherwise
it scans the whole lockfile. The job fails when a dependency is blocked.

**Inputs** (all optional): `ecosystem` (default `npm`), `lockfile` (default per-ecosystem),
`base` (explicit base lockfile), `strict` (treat WARN as failure), `deep` (inspect install
scripts), `version` (Guard release, default `latest`), `fail-on-block` (default `true`),
`sarif-file` (write SARIF for Code Scanning), `args` (extra raw flags).

Upload results to **GitHub Code Scanning** so findings show up inline on the PR:

```yaml
      - uses: tiagosilva07/zyrax-guard@v0.6.0
        with:
          sarif-file: zyrax-guard.sarif
          fail-on-block: "false"   # let Code Scanning surface findings; don't hard-fail
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: zyrax-guard.sarif
```

(That job needs `permissions: { security-events: write }`.)

---

## Ecosystems

Guard supports **npm, PyPI, and crates.io**. Pick one with `--ecosystem` (default `npm`):

```bash
zyrax-guard check --ecosystem pypi requests
zyrax-guard check --ecosystem crates serde
zyrax-guard scan --ecosystem crates              # PR gate over Cargo.lock
zyrax-guard scan --ecosystem pypi               # PR gate over poetry.lock / requirements.txt
```

---

## How the checks work

Guard runs against public registry metadata only — no local execution, no installs, no sandboxing:

| Check | Verdict trigger |
|---|---|
| **Existence** | Package not found on the registry → **BLOCK** (hallucinated or trap name) |
| **Typosquat** | Name is 1 edit away from a far-more-popular package AND has near-zero downloads → **BLOCK** with a "did you mean" suggestion |
| **Known-bad** | OSV advisory match → malware / high-severity → **BLOCK**; low-severity → **WARN** |
| **Age & popularity** | Published < 30 days AND < 50 weekly downloads → **WARN** |
| **Lockfile integrity** | *(scan only)* Resolved URL or integrity hash changed → **BLOCK** |
| **Maintainer change** | *(scan only)* New version published by a previously unseen maintainer → **WARN** |

---

## Deep check (`--deep`)

By default checks are metadata-only (milliseconds). Add `--deep` to also download the
package's distribution artifact and **statically inspect the code it runs at install/build
time** — npm `preinstall`/`install`/`postinstall` scripts, PyPI `setup.py`, crates `build.rs`:

```bash
zyrax-guard check --deep some-pkg
zyrax-guard scan --deep                          # PR gate, deep mode
```

It flags red-flag patterns — network calls, process spawning, base64/obfuscated `eval` —
and **BLOCKs** on dangerous combinations (e.g. "download a script and run it"). It runs
**no code** (purely static) and is **best-effort**: if the artifact cannot be fetched you
get an informational note, never a false block.

Zero added dependencies — the extractor uses stdlib `archive/tar` + `compress/gzip` only.

---

## The three verdicts

| Verdict | Meaning | Default exit code |
|---|---|---|
| **SAFE** | No signals worth noting | `0` |
| **WARN** | Suspicious — review before proceeding | `0` (use `--strict` to make it `1`) |
| **BLOCK** | Strong indicator of malicious or hallucinated package | `1` |

---

## Make it automatic — shell hook

The shell hook intercepts `npm install` / `pip install` / `cargo add` transparently.
Every new package gets checked before the real installer runs; already-installed and
non-install commands pass through untouched.

### macOS / Linux (bash or zsh)

Add to `~/.bashrc`, `~/.zshrc`, or `~/.bash_profile`:

```bash
# Gate npm installs (default)
eval "$(zyrax-guard init bash)"

# Gate pip installs
eval "$(zyrax-guard init bash pip)"

# Gate cargo add
eval "$(zyrax-guard init bash cargo)"
```

Apply immediately without restarting your terminal:

```bash
source ~/.zshrc        # or ~/.bashrc
```

### Windows (PowerShell)

Add to your PowerShell profile (`$PROFILE`). To find and open it:

```powershell
notepad $PROFILE      # creates the file if it doesn't exist
```

Add this line and save:

```powershell
Invoke-Expression (zyrax-guard init powershell | Out-String)
```

Apply immediately:

```powershell
. $PROFILE
```

From now on every `npm install`, `pip install`, or `cargo add` in a PowerShell window
is automatically checked before anything installs.

---

## Using with AI coding agents

AI agents sometimes hallucinate package names. Attackers pre-register those names as
malware. Guard breaks that attack chain by checking every package before the agent ever
runs an install.

### Claude Code CLI

Register Guard as a persistent MCP tool so Claude checks packages automatically:

```bash
claude mcp add zyrax-guard -- zyrax-guard mcp
```

That's it. Claude Code now has a `check_package` tool it calls before suggesting
`npm install` / `pip install` / `cargo add`. To enable the deep install-script check:

```bash
claude mcp add zyrax-guard -- zyrax-guard mcp
```

Then in a Claude Code session, Guard's `check_package` tool accepts a `deep` boolean:

```
check_package(name="some-pkg", ecosystem="npm", deep=true)
```

You can also add a rule to your `CLAUDE.md`:

```markdown
## Dependency policy
Before installing any package, use the zyrax-guard MCP tool to check it.
Never install a BLOCK result. Treat WARN as a prompt to confirm with the user.
```

### Cursor

Add to `.cursor/mcp.json` in your project root (or the global `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "zyrax-guard": {
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  }
}
```

Restart Cursor. The agent now has access to `check_package` before installing anything.

### Windsurf

Add to `.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "zyrax-guard": {
      "command": "zyrax-guard",
      "args": ["mcp"],
      "description": "Check npm/PyPI/crates packages for malware and typosquats before installing"
    }
  }
}
```

### VS Code (GitHub Copilot / Copilot Chat)

Add to your VS Code `settings.json`:

```json
{
  "github.copilot.chat.mcp.servers": {
    "zyrax-guard": {
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  }
}
```

Or add to `.vscode/mcp.json` in your project:

```json
{
  "servers": {
    "zyrax-guard": {
      "type": "stdio",
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  }
}
```

### Continue.dev

Add to `~/.continue/config.json`:

```json
{
  "mcpServers": [
    {
      "name": "zyrax-guard",
      "command": "zyrax-guard",
      "args": ["mcp"]
    }
  ]
}
```

### How the MCP tool works

Once registered, the agent has access to `check_package`:

```json
{
  "name": "check_package",
  "arguments": {
    "name": "lodahs",
    "ecosystem": "npm",
    "deep": false
  }
}
```

Returns:

```json
{
  "verdict": "BLOCK",
  "reasons": ["MAL-2025-25502: Malicious code in lodahs (npm)"],
  "didYouMean": "lodash"
}
```

A `BLOCK` is a normal result (not an MCP error) — the agent should stop and tell the user
rather than proceeding with the install.

---

## Using in CI

### GitHub Actions (PR gate)

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
          zyrax-guard scan \
            --base /tmp/base-lock.json \
            --head package-lock.json \
            --strict \
            --sarif > guard.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: guard.sarif }
```

It checks only **newly added or changed** dependencies (fast, no re-flagging the whole
tree), fails the PR on any BLOCK, and uploads results to GitHub Code Scanning.

### PyPI in CI

```bash
git show "origin/$BASE_REF:poetry.lock" > /tmp/base-lock.txt 2>/dev/null || echo "" > /tmp/base-lock.txt
zyrax-guard scan --ecosystem pypi \
  --base /tmp/base-lock.txt \
  --head poetry.lock \
  --sarif --strict > guard.sarif
```

### crates.io in CI

```bash
git show "origin/$BASE_REF:Cargo.lock" > /tmp/base-lock.txt 2>/dev/null || echo "" > /tmp/base-lock.txt
zyrax-guard scan --ecosystem crates \
  --base /tmp/base-lock.txt \
  --head Cargo.lock \
  --sarif --strict > guard.sarif
```

---

## Privacy promise

Only the **public package names you query** leave your machine, as read-only lookups
against public registry APIs:

- `registry.npmjs.org` — existence and metadata
- `api.npmjs.org` — download counts
- `api.osv.dev` — known advisories

No telemetry. No account. No secrets sent anywhere. The binary is reproducible
(`-trimpath`), and every release ships SLSA L3 provenance so you can verify the build
chain yourself.

---

## Free & open source

Zyrax Guard is **MIT-licensed and free** — every check, the PR gate, the MCP server, the
shell hook, and the JSON/SARIF output. Read the code and verify the binary yourself.

A **Zyrax platform** for teams (organization-wide policy, continuous monitoring, dashboards,
and audit/compliance reporting) is in development. Learn more and join the early-access
waitlist at **[zyrax.io](https://zyrax.io)**.

---

## Roadmap

| Phase | Item |
|---|---|
| **v1** | npm CLI + PR gate + JSON/SARIF + self-hardening — shipped |
| **v1.1** | MCP server (`check_package`) + shell-hook (`zyrax-guard init`) — shipped |
| **v1.2** | PyPI + crates.io across check/install/hook/MCP/scan — shipped |
| **v1.3** | Deep check (`--deep`): static install/build-script analysis — shipped |
| **v0.5.0** | Rebrand to Zyrax; public release — shipped |

The roadmap items drop in via the existing `Ecosystem`, `ThreatIntel`, `Policy`, and
`Reporter` seams — no re-architecting required.

---

## License

MIT — see [LICENSE](LICENSE).
