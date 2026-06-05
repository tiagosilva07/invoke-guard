# Contributing to Zyrax Guard

Thanks for helping make dependency vetting better. This document covers everything you
need to build, test, and submit changes.

---

## Build

```bash
go build ./...
```

The binary ends up at `./zyrax-guard` (or `zyrax-guard.exe` on Windows).

No third-party dependencies — the module is stdlib-only at runtime. If a PR adds an
import outside the standard library, it will be rejected.

## Test

```bash
go test ./...
```

All tests use `testing` only (no testify). Table-driven. No live network — all HTTP calls
are intercepted via `httptest.NewServer`.

To run with the race detector (required before opening a PR):

```bash
go test -race ./...
```

To run the fuzz target for a quick smoke:

```bash
go test -run x -fuzz FuzzDamerau -fuzztime 10s ./internal/check/
```

## Format and vet

```bash
gofmt -l .         # must print nothing (no unformatted files)
go vet ./...       # must be clean
```

CI enforces both. Fix formatting with `gofmt -w .`.

---

## Adding a denylist entry

The bundled denylist lives in `internal/intel/denylist.go`. It is a small, curated set
of **known-malicious** npm package names (not vulnerable, but malicious — the kind the
npm security team removes).

To add an entry:

1. Find a public, confirmed-malicious npm package — e.g. from npm's blog, OSV, or a
   reputable security report.
2. Add it to the `denylist` map in `internal/intel/denylist.go`:

```go
var denylist = map[string]map[string]bool{
    "npm": {
        "crossenv":      true,
        "cross-env.js":  true,
        "your-new-entry": true,  // link to the source report in a comment
    },
}
```

3. Add a test in `internal/intel/osv_test.go` (or a new `denylist_test.go`) asserting
   `InDenylist("npm", "your-new-entry")` returns `true`.
4. Open a PR. Include a link to the public advisory or report.

The denylist is a public-knowledge layer of confirmed-malicious names — do not add
speculative or unconfirmed entries here.

---

## Refreshing the popular-package list

The bundled popular list (at `internal/data/popular-npm.json`) seeds the typosquat check.
It is committed so the binary is self-contained. Refresh it with:

```bash
bash scripts/refresh-popular.sh
```

The script queries the public npm search API and writes the result back to
`internal/data/popular-npm.json`. Commit the updated file.

Refresh cadence: quarterly, or whenever the typosquat false-positive tests start
failing on real popular packages that have been renamed/deprecated.

---

## Security stance

Zyrax Guard is itself a security tool. These invariants must **never regress**:

### Command-injection safety

Package-manager invocations use Go's `exec.Command` with an argument array — never a
shell string. Every name is validated against the npm name grammar by `ValidateName`
before it reaches an exec call. If you add a new exec path, it must use the same
argument-array pattern. A reviewer will reject any PR that constructs a shell command
string from user-supplied input.

### SSRF allowlist

The HTTP client (`internal/httpx/client.go`) only contacts hosts in an explicit
allowlist (`registry.npmjs.org`, `api.npmjs.org`, `api.osv.dev`). If you add a new
network call, extend the allowlist in the call site — do not use a general-purpose HTTP
client that can reach arbitrary hosts.

### Reporting vulnerabilities

Please **do not open a public issue** for security vulnerabilities. Report them privately
via GitHub's Security Advisory feature (the "Report a vulnerability" button on the
Security tab), or by emailing the maintainers directly. We aim to respond within 48 hours
and to publish a fix and advisory within 14 days.

---

## Pull request checklist

- [ ] `go build ./...` passes
- [ ] `go test -race ./...` passes
- [ ] `gofmt -l .` prints nothing
- [ ] `go vet ./...` prints nothing
- [ ] No new third-party imports
- [ ] Command-injection and SSRF invariants intact
- [ ] New denylist entries link to a public report
