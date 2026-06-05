# Invoke Guard v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the v1 of Invoke Guard — a Go single-binary CLI that vets npm dependencies *before* install (and at PR time) and returns SAFE / WARN / BLOCK.

**Architecture:** A pure, ecosystem-agnostic **verdict engine** consumes `Signal`s and decides the verdict. Everything ecosystem- or business-specific sits behind four interfaces (`Ecosystem`, `ThreatIntel`, `Policy`, `Reporter`) so the engine never changes and roadmap items drop in. Build bottom-up: engine → seams → hardened HTTP → npm provider → checks → reporters → orchestrator → CLI → PR-gate → docs → CI/release.

**Tech Stack:** Go 1.23, **stdlib only** for the tool (no third-party runtime deps — `net/http`, `flag`, `encoding/json`, `testing`). Module path `github.com/tiagosilva07/invoke-guard` (rename once if the repo lands under an org — a one-time module-path change before first release).

**Spec:** `docs/superpowers/specs/2026-06-05-invoke-guard-design.md`

**Conventions for every task:** stdlib `testing` only (no testify); table-driven tests; no live network in tests (use `httptest`); `gofmt` clean; each task ends green + committed.

---

## File structure (target)

```
go.mod  LICENSE  .gitignore  README.md  CONTRIBUTING.md
cmd/invoke-guard/main.go              entry + subcommand dispatch
internal/
  verdict/   types.go engine.go       Verdict/Level/Signal/Result + Decide()  (pure core)
  seam/      seam.go                   Ecosystem/ThreatIntel/Policy/Reporter ifaces + DTOs
  httpx/     client.go                 hardened HTTP client (host allowlist, timeouts)
  ecosystem/npm/ npm.go                npm provider (Exists/Metadata/ValidateName/Install)
  intel/     osv.go denylist.go        OSV provider + bundled denylist
  policy/    localfile.go              .invoke/policy.json provider
  check/     distance.go typosquat.go existence.go popularity.go knownbad.go
             lockfile.go maintainer.go orchestrator.go
  report/    text.go json.go sarif.go  reporters
data/popular-npm.json                  top npm names (committed) + scripts/refresh-popular.sh
docs/ INTEGRATION-INVOKE.md SCHEMA.md
.github/workflows/ ci.yml release.yml
```

---

## Task 1: Scaffold the Go module

**Files:** Create `go.mod`, `.gitignore`, `LICENSE`, `README.md` (stub).

- [ ] **Step 1: Create `go.mod`**
```
module github.com/tiagosilva07/invoke-guard

go 1.23
```

- [ ] **Step 2: Create `.gitignore`**
```
/dist/
/invoke-guard
/invoke-guard.exe
*.out
.invoke/
```

- [ ] **Step 3: Create `LICENSE`** — the standard MIT license text, `Copyright (c) 2026 Invoke`.

- [ ] **Step 4: Create `README.md` stub**
```markdown
# Invoke Guard

Check a dependency **before** you install it. Catches typosquats, known-malicious
packages, and the fake package names AI coding agents sometimes invent.

Status: v1 in development. See `docs/superpowers/specs/` for the design.
```

- [ ] **Step 5: Verify + commit**
Run: `go mod verify && gofmt -l .`
Expected: no output (clean).
```bash
git add go.mod .gitignore LICENSE README.md
git commit -m "chore: scaffold Go module (MIT, stdlib-only)"
```

---

## Task 2: Verdict domain types + engine (the pure core)

**Files:** Create `internal/verdict/types.go`, `internal/verdict/engine.go`, `internal/verdict/engine_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/verdict/engine_test.go`
```go
package verdict

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name    string
		signals []Signal
		want    Verdict
		suggest string
	}{
		{"no signals is safe", nil, Safe, ""},
		{"info only is safe", []Signal{{Check: RuleNewAndUnused, Level: LevelInfo, Message: "new"}}, Safe, ""},
		{"a warn signal warns", []Signal{{Check: RuleNewAndUnused, Level: LevelWarn, Message: "new+unused"}}, Warn, ""},
		{"a block signal blocks", []Signal{{Check: RuleNonexistent, Level: LevelBlock, Message: "404"}}, Block, ""},
		{"block beats warn", []Signal{{Check: RuleNewAndUnused, Level: LevelWarn}, {Check: RuleKnownMalware, Level: LevelBlock}}, Block, ""},
		{"suggestion surfaces", []Signal{{Check: RuleTyposquat, Level: LevelBlock, Message: "typo", Suggest: "request"}}, Block, "request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide("npm", "pkg", "1.0.0", tc.signals)
			if got.Verdict != tc.want {
				t.Errorf("verdict = %v, want %v", got.Verdict, tc.want)
			}
			if got.Suggestion != tc.suggest {
				t.Errorf("suggestion = %q, want %q", got.Suggestion, tc.suggest)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	if Block.String() != "BLOCK" || Warn.String() != "WARN" || Safe.String() != "SAFE" {
		t.Fatal("verdict strings wrong")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/verdict && go test ./...`
Expected: FAIL — undefined `Signal`, `Decide`, etc.

- [ ] **Step 3: Implement `internal/verdict/types.go`**
```go
// Package verdict is the pure, ecosystem-agnostic core: it turns Signals into a
// SAFE/WARN/BLOCK Result. It has no I/O and no dependencies outside the stdlib.
package verdict

// Level is the severity a single check contributes.
type Level int

const (
	LevelInfo  Level = iota // contributes context, never escalates past SAFE
	LevelWarn               // escalates to WARN
	LevelBlock             // escalates to BLOCK
)

// Verdict is the overall decision for a package.
type Verdict int

const (
	Safe Verdict = iota
	Warn
	Block
)

func (v Verdict) String() string {
	switch v {
	case Block:
		return "BLOCK"
	case Warn:
		return "WARN"
	default:
		return "SAFE"
	}
}

// Rule IDs — these are the canonical check identifiers and double as SARIF ruleIds.
const (
	RuleNonexistent       = "nonexistent"
	RuleTyposquat         = "typosquat"
	RuleKnownMalware      = "known-malware"
	RuleNewAndUnused      = "new-and-unused"
	RuleLockfileIntegrity = "lockfile-integrity"
	RuleMaintainerChange  = "maintainer-change"
)

// Signal is one check's contribution to the verdict.
type Signal struct {
	Check   string // a Rule* constant
	Level   Level
	Message string // plain-language reason, shown to the user and in SARIF message.text
	Suggest string // optional: a corrected package name (typosquat "did you mean")
}

// Result is the full decision for one package.
type Result struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Verdict    Verdict  `json:"-"`
	VerdictStr string   `json:"verdict"`
	Score      int      `json:"score"`
	Signals    []Signal `json:"signals"`
	Suggestion string   `json:"suggestion,omitempty"`
}
```

- [ ] **Step 4: Implement `internal/verdict/engine.go`**
```go
package verdict

// Decide combines signals into a single Result. BLOCK if any signal is LevelBlock;
// else WARN if any is LevelWarn; else SAFE. Score is a simple weighted sum
// (block=100, warn=10, info=1) so callers can sort by risk. The first non-empty
// Suggest is surfaced as the Result's suggestion.
func Decide(ecosystem, name, version string, signals []Signal) Result {
	v := Safe
	score := 0
	suggestion := ""
	for _, s := range signals {
		switch s.Level {
		case LevelBlock:
			if v < Block {
				v = Block
			}
			score += 100
		case LevelWarn:
			if v < Warn {
				v = Warn
			}
			score += 10
		default:
			score++
		}
		if suggestion == "" && s.Suggest != "" {
			suggestion = s.Suggest
		}
	}
	return Result{
		Ecosystem:  ecosystem,
		Name:       name,
		Version:    version,
		Verdict:    v,
		VerdictStr: v.String(),
		Score:      score,
		Signals:    signals,
		Suggestion: suggestion,
	}
}
```

- [ ] **Step 5: Run tests (PASS) + commit**
Run: `cd internal/verdict && go test ./... -v`
Expected: PASS.
```bash
git add internal/verdict
git commit -m "feat(verdict): pure SAFE/WARN/BLOCK engine + domain types"
```

---

## Task 3: Seam interfaces + shared DTOs

**Files:** Create `internal/seam/seam.go`, `internal/seam/seam_test.go`.

- [ ] **Step 1: Write the failing test** (a compile-time fake proving the interfaces are usable) — `internal/seam/seam_test.go`
```go
package seam_test

import (
	"context"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

type fakeEco struct{}

func (fakeEco) Name() string { return "npm" }
func (fakeEco) ValidateName(string) error { return nil }
func (fakeEco) Exists(context.Context, string, string) (bool, error) { return true, nil }
func (fakeEco) Metadata(context.Context, string) (seam.Metadata, error) { return seam.Metadata{}, nil }
func (fakeEco) PopularList() []string { return []string{"request"} }
func (fakeEco) Install(context.Context, []string, seam.InstallOpts) error { return nil }

func TestEcosystemSatisfiable(t *testing.T) {
	var _ seam.Ecosystem = fakeEco{} // compile-time assertion
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/seam && go test ./...`
Expected: FAIL — undefined `seam.Ecosystem`, `seam.Metadata`.

- [ ] **Step 3: Implement `internal/seam/seam.go`**
```go
// Package seam defines the four interfaces that keep the verdict engine
// ecosystem- and business-agnostic: Ecosystem, ThreatIntel, Policy, Reporter.
// v1 ships only the OSS implementations; paid providers are future drop-ins.
package seam

import (
	"context"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// Metadata is the registry facts a check needs.
type Metadata struct {
	Published   time.Time
	WeeklyLoads int
	Maintainers []string // stable identifiers (e.g. npm usernames)
	RepoURL     string
	Exists      bool
}

// Advisory is one known-bad record (from OSV or the bundled denylist).
type Advisory struct {
	ID       string
	Severity string // "critical","high","medium","low"
	Summary  string
	Malware  bool // true = known-malicious package, not merely vulnerable
}

// InstallOpts controls the real install run.
type InstallOpts struct {
	IgnoreScripts bool
}

// Ecosystem abstracts a package registry + its installer. npm in v1.
type Ecosystem interface {
	Name() string
	ValidateName(name string) error // reject anything off the legal grammar
	Exists(ctx context.Context, name, version string) (bool, error)
	Metadata(ctx context.Context, name string) (Metadata, error)
	PopularList() []string
	Install(ctx context.Context, names []string, opts InstallOpts) error
}

// ThreatIntel returns known-bad records. OSS = OSV + denylist; paid = curated feed.
type ThreatIntel interface {
	Lookup(ctx context.Context, ecosystem, name, version string) ([]Advisory, error)
}

// Decision is a Policy outcome for a package.
type Decision int

const (
	Defer Decision = iota // no opinion — let the checks decide
	ForceAllow            // explicitly allowed — short-circuit to SAFE
	ForceDeny             // explicitly denied — short-circuit to BLOCK
)

// Policy is the local (OSS) or org (paid) allow/deny source.
type Policy interface {
	Decide(name string) Decision
	Allow(name string) error // persist an allowlist entry
}

// Reporter renders results. OSS = text/json/sarif; paid = platform push.
type Reporter interface {
	Report(results []verdict.Result) error
}
```

- [ ] **Step 4: Run tests (PASS) + commit**
Run: `cd internal/seam && go test ./...` then `go build ./...` from repo root.
Expected: PASS / builds.
```bash
git add internal/seam
git commit -m "feat(seam): Ecosystem/ThreatIntel/Policy/Reporter interfaces + DTOs"
```

---

## Task 4: Hardened HTTP client

**Files:** Create `internal/httpx/client.go`, `internal/httpx/client_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/httpx/client_test.go`
```go
package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetJSON_AllowedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	var out struct{ OK bool `json:"ok"` }
	code, err := c.GetJSON(context.Background(), srv.URL, &out)
	if err != nil || code != 200 || !out.OK {
		t.Fatalf("code=%d err=%v out=%+v", code, err, out)
	}
}

func TestGetJSON_DisallowedHost(t *testing.T) {
	c := New([]string{"registry.npmjs.org"})
	_, err := c.GetJSON(context.Background(), "http://169.254.169.254/latest/meta-data", nil)
	if err == nil {
		t.Fatal("expected host-not-allowed error (SSRF guard)")
	}
}

func TestGetJSON_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	code, err := c.GetJSON(context.Background(), srv.URL, nil)
	if code != 404 || err != nil {
		t.Fatalf("want 404,nil got code=%d err=%v", code, err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/httpx && go test ./...`
Expected: FAIL — undefined `New`, `GetJSON`.

- [ ] **Step 3: Implement `internal/httpx/client.go`**
```go
// Package httpx is a hardened read-only HTTP/JSON client: it only talks to an
// allowlist of registry hosts, never follows redirects to other hosts, and always
// times out. This is the SSRF guard for the whole tool.
package httpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	allowed map[string]bool
	hc      *http.Client
}

// New builds a client that will only contact hosts in allow (host or host:port).
func New(allow []string) *Client {
	m := make(map[string]bool, len(allow))
	for _, h := range allow {
		m[h] = true
	}
	c := &Client{allowed: m}
	c.hc = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.hostAllowed(req.URL) {
				return fmt.Errorf("redirect to disallowed host %q blocked", req.URL.Host)
			}
			return nil
		},
	}
	return c
}

func (c *Client) hostAllowed(u *url.URL) bool {
	return c.allowed[u.Host] || c.allowed[u.Hostname()]
}

// GetJSON GETs url and, on 200, decodes the body into out (may be nil to skip).
// Returns the HTTP status code. A non-2xx is not an error (callers branch on code);
// transport/SSRF problems are errors.
func (c *Client) GetJSON(ctx context.Context, rawurl string, out any) (int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return 0, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if !c.hostAllowed(u) {
		return 0, fmt.Errorf("host %q not in allowlist (SSRF guard)", u.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, nil
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode: %w", err)
		}
	}
	return resp.StatusCode, nil
}
```

- [ ] **Step 4: Run tests (PASS) + commit**
Run: `cd internal/httpx && go test ./... -v`
Expected: PASS.
```bash
git add internal/httpx
git commit -m "feat(httpx): hardened allowlist HTTP/JSON client (SSRF guard)"
```

---

## Task 5: npm Ecosystem provider

**Files:** Create `internal/ecosystem/npm/npm.go`, `internal/ecosystem/npm/npm_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/ecosystem/npm/npm_test.go`
```go
package npm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/httpx"
)

func newTestProvider(t *testing.T, h http.Handler) *Provider {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")
	p := New(httpx.New([]string{host}), []string{"request", "express"})
	p.registryBase = srv.URL // test seam
	p.downloadsBase = srv.URL
	return p
}

func TestValidateName(t *testing.T) {
	p := New(nil, nil)
	for _, ok := range []string{"express", "@scope/pkg", "lodash.merge"} {
		if err := p.ValidateName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"foo;rm -rf", "../evil", "UPPER", ""} {
		if err := p.ValidateName(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExistsAndMetadata(t *testing.T) {
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/express"):
			w.Write([]byte(`{"time":{"created":"2010-01-01T00:00:00Z"},"maintainers":[{"name":"tj"}],"repository":{"url":"git+https://github.com/expressjs/express.git"}}`))
		case strings.Contains(r.URL.Path, "/point/last-week/"):
			w.Write([]byte(`{"downloads":30000000}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	ctx := context.Background()
	ok, err := p.Exists(ctx, "express", "")
	if err != nil || !ok {
		t.Fatalf("express should exist: ok=%v err=%v", ok, err)
	}
	md, err := p.Metadata(ctx, "express")
	if err != nil || md.WeeklyLoads != 30000000 || len(md.Maintainers) != 1 {
		t.Fatalf("metadata wrong: %+v err=%v", md, err)
	}
	miss, _ := p.Exists(ctx, "definitely-not-real-xyz", "")
	if miss {
		t.Fatal("nonexistent package reported as existing")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/ecosystem/npm && go test ./...`
Expected: FAIL — undefined `New`, `Provider`.

- [ ] **Step 3: Implement `internal/ecosystem/npm/npm.go`**
```go
// Package npm implements seam.Ecosystem for the public npm registry. All registry
// access is read-only metadata; installs use an argument-array exec (never a shell
// string) so a hostile package name can never inject a command.
package npm

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/httpx"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

const (
	RegistryHost  = "registry.npmjs.org"
	DownloadsHost = "api.npmjs.org"
)

// nameRe is the npm name grammar: optional @scope/, lowercase, digits, and . _ -
var nameRe = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$`)

type Provider struct {
	http          *httpx.Client
	popular       []string
	registryBase  string
	downloadsBase string
}

// New builds the npm provider. http must allow RegistryHost + DownloadsHost.
func New(client *httpx.Client, popular []string) *Provider {
	return &Provider{
		http:          client,
		popular:       popular,
		registryBase:  "https://" + RegistryHost,
		downloadsBase: "https://" + DownloadsHost,
	}
}

func (p *Provider) Name() string { return "npm" }

// ValidateName enforces the npm name grammar and a length bound. Anything else is
// rejected before it can reach a URL or an exec arg.
func (p *Provider) ValidateName(name string) error {
	if len(name) == 0 || len(name) > 214 {
		return fmt.Errorf("invalid npm name length")
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%q is not a legal npm package name", name)
	}
	return nil
}

func (p *Provider) PopularList() []string { return p.popular }

func (p *Provider) Exists(ctx context.Context, name, _ string) (bool, error) {
	if err := p.ValidateName(name); err != nil {
		return false, err
	}
	code, err := p.http.GetJSON(ctx, p.registryBase+"/"+name, nil)
	if err != nil {
		return false, err
	}
	return code == 200, nil
}

type packument struct {
	Time        struct{ Created time.Time `json:"created"` } `json:"time"`
	Maintainers []struct{ Name string `json:"name"` }       `json:"maintainers"`
	Repository  struct{ URL string `json:"url"` }           `json:"repository"`
}

type downloadsPoint struct {
	Downloads int `json:"downloads"`
}

func (p *Provider) Metadata(ctx context.Context, name string) (seam.Metadata, error) {
	if err := p.ValidateName(name); err != nil {
		return seam.Metadata{}, err
	}
	var pk packument
	code, err := p.http.GetJSON(ctx, p.registryBase+"/"+name, &pk)
	if err != nil {
		return seam.Metadata{}, err
	}
	if code != 200 {
		return seam.Metadata{Exists: false}, nil
	}
	md := seam.Metadata{
		Exists:    true,
		Published: pk.Time.Created,
		RepoURL:   pk.Repository.URL,
	}
	for _, m := range pk.Maintainers {
		md.Maintainers = append(md.Maintainers, m.Name)
	}
	var dl downloadsPoint
	if _, err := p.http.GetJSON(ctx, p.downloadsBase+"/downloads/point/last-week/"+name, &dl); err == nil {
		md.WeeklyLoads = dl.Downloads
	}
	return md, nil
}

// Install runs the real `npm install`, passing names as ARGUMENT ARRAY entries.
// Names are re-validated here as defense in depth — they never touch a shell.
func (p *Provider) Install(ctx context.Context, names []string, opts seam.InstallOpts) error {
	for _, n := range names {
		if err := p.ValidateName(n); err != nil {
			return err
		}
	}
	args := []string{"install"}
	if opts.IgnoreScripts {
		args = append(args, "--ignore-scripts")
	}
	args = append(args, names...)
	cmd := exec.CommandContext(ctx, "npm", args...) // arg array — no shell
	cmd.Stdout, cmd.Stderr = stdout(), stderr()
	return cmd.Run()
}
```
And add `internal/ecosystem/npm/io.go`:
```go
package npm

import (
	"io"
	"os"
)

func stdout() io.Writer { return os.Stdout }
func stderr() io.Writer { return os.Stderr }
```

- [ ] **Step 4: Run tests (PASS) + commit**
Run: `cd internal/ecosystem/npm && go test ./... -v`
Expected: PASS.
```bash
git add internal/ecosystem/npm
git commit -m "feat(npm): registry provider — exists/metadata + arg-array install"
```

---

## Task 6: Damerau-Levenshtein + typosquat check (+ fuzz)

**Files:** Create `internal/check/distance.go`, `internal/check/typosquat.go`, `internal/check/distance_test.go`, `internal/check/typosquat_test.go`, `internal/check/fuzz_test.go`.

- [ ] **Step 1: Write the failing distance test** — `internal/check/distance_test.go`
```go
package check

import "testing"

func TestDamerau(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"request", "request", 0},
		{"reqeust", "request", 1}, // transposition
		{"expres", "express", 1},  // deletion
		{"lodahs", "lodash", 1},   // transposition
		{"abc", "xyz", 3},
	}
	for _, c := range cases {
		if got := Damerau(c.a, c.b); got != c.want {
			t.Errorf("Damerau(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/check && go test -run TestDamerau ./...`
Expected: FAIL — undefined `Damerau`.

- [ ] **Step 3: Implement `internal/check/distance.go`**
```go
package check

// Damerau computes the Damerau-Levenshtein distance (optimal string alignment)
// between a and b, counting insertions, deletions, substitutions, and adjacent
// transpositions each as 1.
func Damerau(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min3(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := d[i-2][j-2] + 1; t < d[i][j] {
					d[i][j] = t
				}
			}
		}
	}
	return d[la][lb]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
```

- [ ] **Step 4: Run distance test (PASS)**
Run: `cd internal/check && go test -run TestDamerau ./...`
Expected: PASS.

- [ ] **Step 5: Write the failing typosquat test** — `internal/check/typosquat_test.go`
```go
package check

import (
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestTyposquat(t *testing.T) {
	popular := []string{"request", "express", "lodash", "react"}
	// queried name, its own weekly downloads, want level, want suggest
	cases := []struct {
		name    string
		loads   int
		level   verdict.Level
		suggest string
	}{
		{"express", 5_000_000, verdict.LevelInfo, ""},      // is itself popular → no flag
		{"reqeust", 3, verdict.LevelBlock, "request"},       // dist 1 + near-zero downloads → BLOCK
		{"requests", 5000, verdict.LevelWarn, "request"},    // dist 1 but actually USED → WARN, not BLOCK
		{"totally-unrelated", 5, verdict.LevelInfo, ""},     // far from all → nothing
	}
	for _, c := range cases {
		s := Typosquat(c.name, c.loads, popular)
		if s.Level != c.level || s.Suggest != c.suggest {
			t.Errorf("%q: got level=%v suggest=%q want level=%v suggest=%q", c.name, s.Level, s.Suggest, c.level, c.suggest)
		}
	}
}
```

- [ ] **Step 6: Run to verify it fails**
Run: `cd internal/check && go test -run TestTyposquat ./...`
Expected: FAIL — undefined `Typosquat`.

- [ ] **Step 7: Implement `internal/check/typosquat.go`**
```go
package check

import (
	"fmt"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// Thresholds (conservative defaults; see spec §13 open question 1).
const (
	blockDistance   = 1  // <= this distance to a popular name
	warnDistance    = 2  // <= this distance (but > blockDistance) → WARN
	lowDownloads    = 50 // queried package itself this-or-fewer weekly downloads
)

// Typosquat flags a name that is a near-miss of a much-more-popular package while
// itself having near-zero usage. An exact match to a popular name is the popular
// package itself → no flag. Returns a verdict.Signal (LevelInfo if nothing fires).
func Typosquat(name string, ownLoads int, popular []string) verdict.Signal {
	best, bestDist := "", 1<<30
	for _, p := range popular {
		if p == name {
			return verdict.Signal{Check: verdict.RuleTyposquat, Level: verdict.LevelInfo}
		}
		if dd := Damerau(name, p); dd < bestDist {
			best, bestDist = p, dd
		}
	}
	switch {
	case bestDist <= blockDistance && ownLoads <= lowDownloads:
		return verdict.Signal{
			Check:   verdict.RuleTyposquat,
			Level:   verdict.LevelBlock,
			Message: fmt.Sprintf("looks like a typo of %q (far more popular); this name has only %d weekly downloads", best, ownLoads),
			Suggest: best,
		}
	case bestDist <= warnDistance:
		return verdict.Signal{
			Check:   verdict.RuleTyposquat,
			Level:   verdict.LevelWarn,
			Message: fmt.Sprintf("name is similar to %q — double-check you meant this package", best),
			Suggest: best,
		}
	}
	return verdict.Signal{Check: verdict.RuleTyposquat, Level: verdict.LevelInfo}
}
```

- [ ] **Step 8: Add the fuzz target** — `internal/check/fuzz_test.go`
```go
package check

import "testing"

func FuzzDamerau(f *testing.F) {
	f.Add("request", "reqeust")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, a, b string) {
		d := Damerau(a, b)
		if d < 0 {
			t.Fatalf("negative distance %d", d)
		}
		if a == b && d != 0 {
			t.Fatalf("equal strings have distance %d", d)
		}
	})
}
```

- [ ] **Step 9: Run all check tests + a fuzz smoke (PASS) + commit**
Run: `cd internal/check && go test ./... && go test -run x -fuzz FuzzDamerau -fuzztime 5s ./...`
Expected: PASS; fuzz finds no crash.
```bash
git add internal/check/distance.go internal/check/typosquat.go internal/check/distance_test.go internal/check/typosquat_test.go internal/check/fuzz_test.go
git commit -m "feat(check): Damerau-Levenshtein + typosquat detection (+fuzz)"
```

---

## Task 7: Existence + popularity checks

**Files:** Create `internal/check/existence.go`, `internal/check/popularity.go`, `internal/check/existence_test.go`, `internal/check/popularity_test.go`.

- [ ] **Step 1: Write the failing tests** — `internal/check/existence_test.go`
```go
package check

import (
	"testing"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestExistence(t *testing.T) {
	if s := Existence(false); s.Level != verdict.LevelBlock {
		t.Errorf("missing package should BLOCK, got %v", s.Level)
	}
	if s := Existence(true); s.Level != verdict.LevelInfo {
		t.Errorf("existing package should be info, got %v", s.Level)
	}
}

func TestPopularity(t *testing.T) {
	now := time.Now()
	newLow := seam.Metadata{Exists: true, Published: now.AddDate(0, 0, -5), WeeklyLoads: 10}
	if s := Popularity(newLow); s.Level != verdict.LevelWarn {
		t.Errorf("new+low should WARN, got %v", s.Level)
	}
	old := seam.Metadata{Exists: true, Published: now.AddDate(-5, 0, 0), WeeklyLoads: 9_000_000}
	if s := Popularity(old); s.Level != verdict.LevelInfo {
		t.Errorf("old+popular should be info, got %v", s.Level)
	}
}
```
And `internal/check/popularity_test.go` may stay empty (covered above) — put both in `existence_test.go`. (Delete the empty file requirement: create only `existence_test.go`.)

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/check && go test -run 'TestExistence|TestPopularity' ./...`
Expected: FAIL — undefined `Existence`, `Popularity`.

- [ ] **Step 3: Implement `internal/check/existence.go`**
```go
package check

import "github.com/tiagosilva07/invoke-guard/internal/verdict"

// Existence turns a registry existence result into a signal. A non-existent
// package is a strong signal of a hallucinated or trap name → BLOCK.
func Existence(exists bool) verdict.Signal {
	if !exists {
		return verdict.Signal{
			Check:   verdict.RuleNonexistent,
			Level:   verdict.LevelBlock,
			Message: "package does not exist on the registry — likely a hallucinated or trap name",
		}
	}
	return verdict.Signal{Check: verdict.RuleNonexistent, Level: verdict.LevelInfo}
}
```

- [ ] **Step 4: Implement `internal/check/popularity.go`**
```go
package check

import (
	"fmt"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

const (
	newAgeDays    = 30
	lowWeeklyLoad = 50
)

// Popularity flags packages that are both very new and barely used. It never
// blocks on its own — it raises suspicion (WARN) to be combined with other signals.
func Popularity(md seam.Metadata) verdict.Signal {
	if !md.Exists || md.Published.IsZero() {
		return verdict.Signal{Check: verdict.RuleNewAndUnused, Level: verdict.LevelInfo}
	}
	ageDays := int(time.Since(md.Published).Hours() / 24)
	if ageDays < newAgeDays && md.WeeklyLoads < lowWeeklyLoad {
		return verdict.Signal{
			Check:   verdict.RuleNewAndUnused,
			Level:   verdict.LevelWarn,
			Message: fmt.Sprintf("published %d days ago with only %d weekly downloads", ageDays, md.WeeklyLoads),
		}
	}
	return verdict.Signal{Check: verdict.RuleNewAndUnused, Level: verdict.LevelInfo}
}
```

- [ ] **Step 5: Run tests (PASS) + commit**
Run: `cd internal/check && go test ./...`
Expected: PASS.
```bash
git add internal/check/existence.go internal/check/popularity.go internal/check/existence_test.go
git commit -m "feat(check): existence + age/popularity signals"
```

---

## Task 8: OSV ThreatIntel provider + known-bad check + denylist

**Files:** Create `internal/intel/osv.go`, `internal/intel/denylist.go`, `internal/intel/osv_test.go`, `internal/check/knownbad.go`, `internal/check/knownbad_test.go`.

- [ ] **Step 1: Write the failing OSV test** — `internal/intel/osv_test.go`
```go
package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/httpx"
)

func TestOSVLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"MAL-123","summary":"malware","database_specific":{"severity":"CRITICAL"}}]}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	o := NewOSV(httpx.New([]string{host}))
	o.base = srv.URL
	advs, err := o.Lookup(context.Background(), "npm", "evil", "1.0.0")
	if err != nil || len(advs) != 1 || !advs[0].Malware {
		t.Fatalf("advs=%+v err=%v", advs, err)
	}
}

func TestDenylist(t *testing.T) {
	if !InDenylist("npm", "known-evil-pkg") {
		t.Skip("seed denylist may be empty in v1; ensure InDenylist exists")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/intel && go test ./...`
Expected: FAIL — undefined `NewOSV`, `InDenylist`.

- [ ] **Step 3: Implement `internal/intel/denylist.go`**
```go
// Package intel implements seam.ThreatIntel using public OSV data plus a small
// bundled denylist of known-malicious package names (seed; grow via PRs).
package intel

// denylist maps ecosystem -> set of known-malicious names. Seeded small; this is
// the OSS, public-knowledge list (the paid curated feed is a separate provider).
var denylist = map[string]map[string]bool{
	"npm": {
		// Examples of historically malicious typo/confusion names. Extend via PR.
		"crossenv":      true,
		"cross-env.js":  true,
	},
}

// InDenylist reports whether name is a known-malicious package in ecosystem.
func InDenylist(ecosystem, name string) bool {
	return denylist[ecosystem][name]
}
```

- [ ] **Step 4: Implement `internal/intel/osv.go`**
```go
package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tiagosilva07/invoke-guard/internal/httpx"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

// OSV queries https://api.osv.dev for advisories. It also folds in the bundled
// denylist so a denylisted name always yields a malware advisory.
type OSV struct {
	http *httpx.Client
	base string
}

const OSVHost = "api.osv.dev"

func NewOSV(client *httpx.Client) *OSV {
	return &OSV{http: client, base: "https://" + OSVHost}
}

type osvResp struct {
	Vulns []struct {
		ID               string `json:"id"`
		Summary          string `json:"summary"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"vulns"`
}

func (o *OSV) Lookup(ctx context.Context, ecosystem, name, version string) ([]seam.Advisory, error) {
	var out []seam.Advisory
	if InDenylist(ecosystem, name) {
		out = append(out, seam.Advisory{ID: "denylist", Severity: "critical", Summary: "known-malicious package (bundled denylist)", Malware: true})
	}
	body := map[string]any{
		"package": map[string]string{"name": name, "ecosystem": osvEcosystem(ecosystem)},
	}
	if version != "" {
		body["version"] = version
	}
	advs, err := o.query(ctx, body)
	if err != nil {
		return out, err
	}
	return append(out, advs...), nil
}

// query posts to OSV. (httpx is GET-only by design; OSV's query endpoint needs POST,
// so this uses a narrow direct POST through the same host allowlist contract.)
func (o *OSV) query(ctx context.Context, body map[string]any) ([]seam.Advisory, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/v1/query", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	code, raw, err := o.http.PostJSON(req)
	if err != nil || code != 200 {
		return nil, err
	}
	var r osvResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	var out []seam.Advisory
	for _, v := range r.Vulns {
		sev := strings.ToLower(v.DatabaseSpecific.Severity)
		out = append(out, seam.Advisory{
			ID:       v.ID,
			Severity: sev,
			Summary:  v.Summary,
			Malware:  strings.HasPrefix(v.ID, "MAL-"), // OSV malware IDs are MAL-*
		})
	}
	return out, nil
}

func osvEcosystem(e string) string {
	switch e {
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "crates":
		return "crates.io"
	}
	return e
}
```
And extend the httpx client with a guarded `PostJSON` — add to `internal/httpx/client.go`:
```go
// PostJSON sends an already-built POST request, enforcing the same host allowlist,
// and returns the status code + raw body (capped). For the few APIs (OSV) that
// require POST. Body must already be set on req.
func (c *Client) PostJSON(req *http.Request) (int, []byte, error) {
	if !c.hostAllowed(req.URL) {
		return 0, nil, fmt.Errorf("host %q not in allowlist (SSRF guard)", req.URL.Host)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, raw, nil
}
```
(Add a matching `TestPostJSON_DisallowedHost` to `client_test.go` asserting a non-allowlisted host errors.)

- [ ] **Step 5: Write + implement the known-bad check** — `internal/check/knownbad_test.go`
```go
package check

import (
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestKnownBad(t *testing.T) {
	if s := KnownBad([]seam.Advisory{{Malware: true, Summary: "malware"}}); s.Level != verdict.LevelBlock {
		t.Errorf("malware should BLOCK, got %v", s.Level)
	}
	if s := KnownBad([]seam.Advisory{{Severity: "high", Summary: "vuln"}}); s.Level != verdict.LevelBlock {
		t.Errorf("high severity should BLOCK, got %v", s.Level)
	}
	if s := KnownBad([]seam.Advisory{{Severity: "low", Summary: "minor"}}); s.Level != verdict.LevelWarn {
		t.Errorf("low severity should WARN, got %v", s.Level)
	}
	if s := KnownBad(nil); s.Level != verdict.LevelInfo {
		t.Errorf("no advisories should be info, got %v", s.Level)
	}
}
```
Implement `internal/check/knownbad.go`:
```go
package check

import (
	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// KnownBad turns advisories into a signal. Malware or high/critical severity →
// BLOCK; anything lower → WARN; none → info.
func KnownBad(advs []seam.Advisory) verdict.Signal {
	worst := verdict.LevelInfo
	msg := ""
	for _, a := range advs {
		switch {
		case a.Malware || a.Severity == "critical" || a.Severity == "high":
			return verdict.Signal{Check: verdict.RuleKnownMalware, Level: verdict.LevelBlock, Message: advMsg(a)}
		default:
			if worst < verdict.LevelWarn {
				worst, msg = verdict.LevelWarn, advMsg(a)
			}
		}
	}
	return verdict.Signal{Check: verdict.RuleKnownMalware, Level: worst, Message: msg}
}

func advMsg(a seam.Advisory) string {
	if a.Summary != "" {
		return a.ID + ": " + a.Summary
	}
	return a.ID
}
```

- [ ] **Step 6: Run all intel + check tests (PASS) + commit**
Run: `cd internal/intel && go test ./... && cd ../check && go test ./...`
Expected: PASS.
```bash
git add internal/intel internal/check/knownbad.go internal/check/knownbad_test.go internal/httpx
git commit -m "feat(intel): OSV provider + denylist + known-bad check"
```

---

## Task 9: Local policy provider

**Files:** Create `internal/policy/localfile.go`, `internal/policy/localfile_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/policy/localfile_test.go`
```go
package policy

import (
	"path/filepath"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

func TestLocalPolicyAllow(t *testing.T) {
	dir := t.TempDir()
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("foo") != seam.Defer {
		t.Fatal("unknown package should Defer")
	}
	if err := p.Allow("foo"); err != nil {
		t.Fatal(err)
	}
	// reload from disk
	p2, _ := Load(dir)
	if p2.Decide("foo") != seam.ForceAllow {
		t.Fatal("allowed package should ForceAllow after reload")
	}
	if _, err := filepath.Rel(dir, p.path); err != nil {
		t.Fatal("policy file must live under the project dir")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/policy && go test ./...`
Expected: FAIL — undefined `Load`.

- [ ] **Step 3: Implement `internal/policy/localfile.go`**
```go
// Package policy implements seam.Policy backed by a project-local committed file
// .invoke/policy.json — the OSS allow/deny source. (Org policy is a paid drop-in.)
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

type file struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

type Local struct {
	path  string
	allow map[string]bool
	deny  map[string]bool
}

// Load reads .invoke/policy.json under projectDir (creating neither dir nor file
// until Allow is called). projectDir bounds all writes (no traversal).
func Load(projectDir string) (*Local, error) {
	p := &Local{
		path:  filepath.Join(projectDir, ".invoke", "policy.json"),
		allow: map[string]bool{},
		deny:  map[string]bool{},
	}
	b, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for _, n := range f.Allow {
		p.allow[n] = true
	}
	for _, n := range f.Deny {
		p.deny[n] = true
	}
	return p, nil
}

func (p *Local) Decide(name string) seam.Decision {
	switch {
	case p.deny[name]:
		return seam.ForceDeny
	case p.allow[name]:
		return seam.ForceAllow
	default:
		return seam.Defer
	}
}

// Allow adds name to the allowlist and persists the file (creating .invoke/).
func (p *Local) Allow(name string) error {
	p.allow[name] = true
	if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
		return err
	}
	var f file
	for n := range p.allow {
		f.Allow = append(f.Allow, n)
	}
	for n := range p.deny {
		f.Deny = append(f.Deny, n)
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.path, b, 0o644)
}
```

- [ ] **Step 4: Run tests (PASS) + commit**
Run: `cd internal/policy && go test ./... -v`
Expected: PASS.
```bash
git add internal/policy
git commit -m "feat(policy): local .invoke/policy.json allow/deny provider"
```

---

## Task 10: Reporters (text / json / sarif) + SARIF golden test

**Files:** Create `internal/report/text.go`, `internal/report/json.go`, `internal/report/sarif.go`, `internal/report/sarif_test.go`.

- [ ] **Step 1: Write the failing SARIF test** — `internal/report/sarif_test.go`
```go
package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestSARIFShapeMatchesPlatform(t *testing.T) {
	res := []verdict.Result{{
		Ecosystem: "npm", Name: "reqeust", Version: "1.0.0", Verdict: verdict.Block, VerdictStr: "BLOCK",
		Signals: []verdict.Signal{{Check: verdict.RuleTyposquat, Level: verdict.LevelBlock, Message: "typo of request"}},
	}}
	var buf bytes.Buffer
	if err := (&SARIF{W: &buf}).Report(res); err != nil {
		t.Fatal(err)
	}
	// Must parse into the platform importer's expected shape.
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string `json:"name"` } `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct{ Text string `json:"text"` } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("sarif not parseable: %v", err)
	}
	r := doc.Runs[0]
	if r.Tool.Driver.Name != "invoke-guard" {
		t.Errorf("driver name = %q", r.Tool.Driver.Name)
	}
	if len(r.Results) != 1 || r.Results[0].RuleID != "typosquat" || r.Results[0].Level != "error" {
		t.Errorf("result wrong: %+v", r.Results)
	}
	if r.Results[0].Message.Text == "" {
		t.Error("message text empty")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/report && go test ./...`
Expected: FAIL — undefined `SARIF`.

- [ ] **Step 3: Implement `internal/report/sarif.go`**
```go
// Package report renders verdict results. SARIF output matches the exact subset the
// Invoke platform's importer reads (tool.driver.name + results[].ruleId/level/message.text),
// so Guard findings ingest into the platform with no platform changes.
package report

import (
	"encoding/json"
	"io"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

type SARIF struct{ W io.Writer }

func levelString(l verdict.Level) string {
	switch l {
	case verdict.LevelBlock:
		return "error"
	case verdict.LevelWarn:
		return "warning"
	default:
		return "note"
	}
}

func (s *SARIF) Report(results []verdict.Result) error {
	type msg struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message msg    `json:"message"`
	}
	var out []result
	for _, r := range results {
		for _, sig := range r.Signals {
			if sig.Level == verdict.LevelInfo {
				continue // only surface what actually fired
			}
			out = append(out, result{
				RuleID:  sig.Check,
				Level:   levelString(sig.Level),
				Message: msg{Text: r.Name + "@" + r.Version + ": " + sig.Message},
			})
		}
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "invoke-guard"}},
			"results": out,
		}},
	}
	enc := json.NewEncoder(s.W)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
```

- [ ] **Step 4: Implement `internal/report/json.go`** (versioned schema)
```go
package report

import (
	"encoding/json"
	"io"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

const SchemaVersion = "1.0"

type JSON struct{ W io.Writer }

func (j *JSON) Report(results []verdict.Result) error {
	doc := map[string]any{
		"schemaVersion": SchemaVersion,
		"results":       results,
	}
	enc := json.NewEncoder(j.W)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
```

- [ ] **Step 5: Implement `internal/report/text.go`**
```go
package report

import (
	"fmt"
	"io"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

type Text struct {
	W     io.Writer
	Color bool
}

func (t *Text) Report(results []verdict.Result) error {
	for _, r := range results {
		mark, col := "✓", "\x1b[32m" // green
		switch r.Verdict {
		case verdict.Block:
			mark, col = "✗", "\x1b[31m" // red
		case verdict.Warn:
			mark, col = "!", "\x1b[33m" // amber
		}
		reset := "\x1b[0m"
		if !t.Color {
			col, reset = "", ""
		}
		fmt.Fprintf(t.W, "%s%s %s@%s — %s%s\n", col, mark, r.Name, r.Version, r.VerdictStr, reset)
		for _, s := range r.Signals {
			if s.Level == verdict.LevelInfo || s.Message == "" {
				continue
			}
			fmt.Fprintf(t.W, "  - %s\n", s.Message)
		}
		if r.Suggestion != "" {
			fmt.Fprintf(t.W, "  did you mean: %s\n", r.Suggestion)
		}
		if r.Verdict == verdict.Block {
			fmt.Fprintf(t.W, "  to override:  invoke-guard allow %s\n", r.Name)
		}
	}
	return nil
}
```

- [ ] **Step 6: Run tests (PASS) + commit**
Run: `cd internal/report && go test ./... -v`
Expected: PASS.
```bash
git add internal/report
git commit -m "feat(report): text/json/sarif reporters (sarif matches platform importer)"
```

---

## Task 11: Orchestrator (vet one package end-to-end)

**Files:** Create `internal/check/orchestrator.go`, `internal/check/orchestrator_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/check/orchestrator_test.go`
```go
package check

import (
	"context"
	"testing"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

type stubEco struct {
	exists bool
	md     seam.Metadata
	pop    []string
}

func (s stubEco) Name() string                                  { return "npm" }
func (s stubEco) ValidateName(string) error                     { return nil }
func (s stubEco) Exists(context.Context, string, string) (bool, error) { return s.exists, nil }
func (s stubEco) Metadata(context.Context, string) (seam.Metadata, error) { return s.md, nil }
func (s stubEco) PopularList() []string                         { return s.pop }
func (s stubEco) Install(context.Context, []string, seam.InstallOpts) error { return nil }

type stubIntel struct{ advs []seam.Advisory }

func (s stubIntel) Lookup(context.Context, string, string, string) ([]seam.Advisory, error) {
	return s.advs, nil
}

type stubPolicy struct{ d seam.Decision }

func (s stubPolicy) Decide(string) seam.Decision { return s.d }
func (s stubPolicy) Allow(string) error          { return nil }

func TestOrchestrator(t *testing.T) {
	old := seam.Metadata{Exists: true, Published: time.Now().AddDate(-5, 0, 0), WeeklyLoads: 9_000_000}
	o := &Orchestrator{
		Eco:    stubEco{exists: true, md: old, pop: []string{"express"}},
		Intel:  stubIntel{},
		Policy: stubPolicy{d: seam.Defer},
	}
	// express-like: safe
	r := o.Check(context.Background(), "express", "")
	if r.Verdict != verdict.Safe {
		t.Errorf("popular old pkg should be SAFE, got %v (%+v)", r.Verdict, r.Signals)
	}
	// typosquat: reqeust with near-zero downloads
	o.Eco = stubEco{exists: true, md: seam.Metadata{Exists: true, WeeklyLoads: 2, Published: time.Now()}, pop: []string{"express", "request"}}
	r = o.Check(context.Background(), "reqeust", "")
	if r.Verdict != verdict.Block || r.Suggestion != "request" {
		t.Errorf("typosquat should BLOCK+suggest, got %v %q", r.Verdict, r.Suggestion)
	}
	// missing: block
	o.Eco = stubEco{exists: false}
	if o.Check(context.Background(), "nope-xyz", "").Verdict != verdict.Block {
		t.Error("missing should BLOCK")
	}
	// policy allow overrides to safe
	o.Eco = stubEco{exists: false}
	o.Policy = stubPolicy{d: seam.ForceAllow}
	if o.Check(context.Background(), "nope-xyz", "").Verdict != verdict.Safe {
		t.Error("policy allow should force SAFE")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/check && go test -run TestOrchestrator ./...`
Expected: FAIL — undefined `Orchestrator`.

- [ ] **Step 3: Implement `internal/check/orchestrator.go`**
```go
package check

import (
	"context"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// Orchestrator runs all package-level checks for one package and applies policy.
type Orchestrator struct {
	Eco    seam.Ecosystem
	Intel  seam.ThreatIntel
	Policy seam.Policy
}

// Check vets one package end-to-end and returns the verdict Result. Policy
// allow/deny short-circuits (with an explanatory signal) before the checks run.
func (o *Orchestrator) Check(ctx context.Context, name, version string) verdict.Result {
	switch o.Policy.Decide(name) {
	case seam.ForceAllow:
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: "policy-allow", Level: verdict.LevelInfo, Message: "explicitly allowed by local policy"},
		})
	case seam.ForceDeny:
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: "policy-deny", Level: verdict.LevelBlock, Message: "explicitly denied by local policy"},
		})
	}

	var signals []verdict.Signal
	exists, _ := o.Eco.Exists(ctx, name, version)
	signals = append(signals, Existence(exists))
	if !exists {
		return verdict.Decide(o.Eco.Name(), name, version, signals)
	}
	md, _ := o.Eco.Metadata(ctx, name)
	signals = append(signals, Typosquat(name, md.WeeklyLoads, o.Eco.PopularList()))
	signals = append(signals, Popularity(md))
	if advs, err := o.Intel.Lookup(ctx, o.Eco.Name(), name, version); err == nil {
		signals = append(signals, KnownBad(advs))
	}
	return verdict.Decide(o.Eco.Name(), name, version, signals)
}
```

- [ ] **Step 4: Run tests (PASS) + commit**
Run: `cd internal/check && go test ./... -v`
Expected: PASS.
```bash
git add internal/check/orchestrator.go internal/check/orchestrator_test.go
git commit -m "feat(check): orchestrator — vet one package end-to-end with policy"
```

---

## Task 12: CLI — check / install / allow + flags + exit codes

**Files:** Create `cmd/invoke-guard/main.go`, `internal/check/wire.go`, `cmd/invoke-guard/main_test.go`.

- [ ] **Step 1: Write the failing test** — `cmd/invoke-guard/main_test.go`
```go
package main

import (
	"strings"
	"testing"
)

func TestExitCodeForVerdict(t *testing.T) {
	if exitForVerdict("BLOCK", false) == 0 {
		t.Error("BLOCK must be non-zero")
	}
	if exitForVerdict("WARN", false) != 0 {
		t.Error("WARN non-strict must be 0")
	}
	if exitForVerdict("WARN", true) == 0 {
		t.Error("WARN strict must be non-zero")
	}
	if exitForVerdict("SAFE", true) != 0 {
		t.Error("SAFE must be 0")
	}
}

func TestUsageMentionsCommands(t *testing.T) {
	if !strings.Contains(usage(), "check") || !strings.Contains(usage(), "scan") {
		t.Error("usage must list commands")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd cmd/invoke-guard && go test ./...`
Expected: FAIL — undefined `exitForVerdict`, `usage`.

- [ ] **Step 3: Implement the wiring helper** — `internal/check/wire.go`
```go
package check

import (
	"github.com/tiagosilva07/invoke-guard/internal/ecosystem/npm"
	"github.com/tiagosilva07/invoke-guard/internal/httpx"
	"github.com/tiagosilva07/invoke-guard/internal/intel"
	"github.com/tiagosilva07/invoke-guard/internal/policy"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

// NewNPM wires the default npm orchestrator: hardened HTTP client allowlisting the
// npm + OSV hosts, the npm provider with the bundled popular list, OSV intel, and
// the project-local policy.
func NewNPM(projectDir string, popular []string) (*Orchestrator, error) {
	client := httpx.New([]string{npm.RegistryHost, npm.DownloadsHost, intel.OSVHost})
	pol, err := policy.Load(projectDir)
	if err != nil {
		return nil, err
	}
	return &Orchestrator{
		Eco:    npm.New(client, popular),
		Intel:  intel.NewOSV(client),
		Policy: pol,
	}, nil
}

var _ seam.Policy = (*policy.Local)(nil)
```

- [ ] **Step 4: Implement `cmd/invoke-guard/main.go`**
```go
// Command invoke-guard vets dependencies before install. Subcommands: check,
// install, allow, scan. Exit 0 for SAFE/WARN; non-zero for BLOCK (and for WARN
// under --strict).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tiagosilva07/invoke-guard/internal/check"
	"github.com/tiagosilva07/invoke-guard/internal/report"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

var version = "dev" // set via -ldflags at release

func usage() string {
	return `invoke-guard — check a dependency before you install it

usage:
  invoke-guard check <name>[@version] [--json|--sarif] [--strict]
  invoke-guard install <names...> [--ignore-scripts] [--strict]
  invoke-guard allow <name>
  invoke-guard scan [--strict] [--json|--sarif]
  invoke-guard --version
`
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(usage())
		return 2
	}
	switch args[0] {
	case "--version", "version":
		fmt.Println(version)
		return 0
	case "--help", "-h", "help":
		fmt.Print(usage())
		return 0
	case "check":
		return cmdCheck(args[1:])
	case "install":
		return cmdInstall(args[1:])
	case "allow":
		return cmdAllow(args[1:])
	case "scan":
		return cmdScan(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", args[0], usage())
		return 2
	}
}

func splitNameVersion(s string) (string, string) {
	if i := strings.LastIndex(s, "@"); i > 0 { // i>0 keeps @scope intact
		return s[:i], s[i+1:]
	}
	return s, ""
}

func reporterFor(asJSON, asSARIF bool) seam.Reporter {
	switch {
	case asSARIF:
		return &report.SARIF{W: os.Stdout}
	case asJSON:
		return &report.JSON{W: os.Stdout}
	default:
		return &report.Text{W: os.Stdout, Color: term()}
	}
}

func term() bool { fi, _ := os.Stdout.Stat(); return fi != nil && (fi.Mode()&os.ModeCharDevice) != 0 }

func exitForVerdict(v string, strict bool) int {
	switch v {
	case "BLOCK":
		return 1
	case "WARN":
		if strict {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	asSARIF := fs.Bool("sarif", false, "SARIF output")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	name, ver := splitNameVersion(fs.Arg(0))
	orch, err := check.NewNPM(".", loadPopular())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	res := orch.Check(context.Background(), name, ver)
	reporterFor(*asJSON, *asSARIF).Report([]verdict.Result{res})
	return exitForVerdict(res.VerdictStr, *strict)
}

func cmdInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	ignoreScripts := fs.Bool("ignore-scripts", false, "pass --ignore-scripts to npm")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	names := fs.Args()
	if len(names) == 0 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	orch, err := check.NewNPM(".", loadPopular())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var results []verdict.Result
	worst := 0
	for _, raw := range names {
		n, v := splitNameVersion(raw)
		r := orch.Check(context.Background(), n, v)
		results = append(results, r)
		if c := exitForVerdict(r.VerdictStr, *strict); c > worst {
			worst = c
		}
	}
	reporterFor(false, false).Report(results)
	if worst != 0 {
		fmt.Fprintln(os.Stderr, "blocked — not installing. Override with: invoke-guard allow <name>")
		return worst
	}
	if err := orch.Eco.Install(context.Background(), bareNames(names), seam.InstallOpts{IgnoreScripts: *ignoreScripts}); err != nil {
		fmt.Fprintln(os.Stderr, "install failed:", err)
		return 1
	}
	return 0
}

func bareNames(raw []string) []string {
	out := make([]string, len(raw))
	for i, r := range raw {
		out[i], _ = splitNameVersion(r)
	}
	return out
}

func cmdAllow(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	orch, err := check.NewNPM(".", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := orch.Policy.Allow(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("allowed %q (recorded in .invoke/policy.json)\n", args[0])
	return 0
}
```
(`cmdScan` and `loadPopular` are added in Tasks 13–15; add a temporary stub now so it compiles:)
```go
func cmdScan(args []string) int { fmt.Fprintln(os.Stderr, "scan: implemented in a later task"); return 2 }
func loadPopular() []string     { return nil }
```

- [ ] **Step 5: Build + run tests (PASS) + commit**
Run: `go build ./... && cd cmd/invoke-guard && go test ./...`
Expected: builds; PASS.
```bash
git add cmd/invoke-guard internal/check/wire.go
git commit -m "feat(cli): check/install/allow commands + exit codes (safe install)"
```

---

## Task 13: Lockfile parse + diff + lockfile-integrity & maintainer-change checks

**Files:** Create `internal/check/lockfile.go`, `internal/check/maintainer.go`, `internal/check/lockfile_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/check/lockfile_test.go`
```go
package check

import (
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestParseLockAdded(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"},"node_modules/b":{"version":"2.0.0","resolved":"https://r/b","integrity":"sha-B"}}}`
	added, changed, err := DiffLockfiles([]byte(base), []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0].Name != "b" {
		t.Fatalf("added = %+v", added)
	}
	if len(changed) != 0 {
		t.Fatalf("changed = %+v", changed)
	}
}

func TestLockIntegrityChanged(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://EVIL/a","integrity":"sha-X"}}}`
	_, changed, _ := DiffLockfiles([]byte(base), []byte(head))
	if len(changed) != 1 {
		t.Fatalf("expected 1 integrity change, got %+v", changed)
	}
	if s := LockfileIntegrity(changed[0]); s.Level != verdict.LevelBlock {
		t.Errorf("integrity change should BLOCK, got %v", s.Level)
	}
}

func TestMaintainerChange(t *testing.T) {
	if s := MaintainerChange([]string{"alice"}, []string{"bob"}); s.Level != verdict.LevelWarn {
		t.Errorf("new maintainer should WARN, got %v", s.Level)
	}
	if s := MaintainerChange([]string{"alice"}, []string{"alice"}); s.Level != verdict.LevelInfo {
		t.Errorf("same maintainer should be info, got %v", s.Level)
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd internal/check && go test -run 'Lock|Maintainer' ./...`
Expected: FAIL — undefined `DiffLockfiles`, `LockfileIntegrity`, `MaintainerChange`.

- [ ] **Step 3: Implement `internal/check/lockfile.go`**
```go
package check

import (
	"encoding/json"
	"strings"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// LockEntry is one resolved package in an npm lockfile (v2/v3 "packages" map).
type LockEntry struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
}

// LockChange records an existing entry whose resolved URL or integrity changed.
type LockChange struct {
	Name             string
	OldResolved, New string
	OldIntegrity     string
	NewIntegrity     string
}

type npmLock struct {
	Packages map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
	} `json:"packages"`
}

func parseLock(b []byte) (map[string]LockEntry, error) {
	var l npmLock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	out := map[string]LockEntry{}
	for path, p := range l.Packages {
		if path == "" { // the root project entry
			continue
		}
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		out[name] = LockEntry{Name: name, Version: p.Version, Resolved: p.Resolved, Integrity: p.Integrity}
	}
	return out, nil
}

// DiffLockfiles returns packages newly added in head, and existing packages whose
// resolved URL or integrity hash changed (the lockfile-poisoning signal).
func DiffLockfiles(base, head []byte) (added []LockEntry, changed []LockChange, err error) {
	b, err := parseLock(base)
	if err != nil {
		return nil, nil, err
	}
	h, err := parseLock(head)
	if err != nil {
		return nil, nil, err
	}
	for name, he := range h {
		be, ok := b[name]
		if !ok {
			added = append(added, he)
			continue
		}
		if be.Resolved != he.Resolved || be.Integrity != he.Integrity {
			changed = append(changed, LockChange{
				Name: name, OldResolved: be.Resolved, New: he.Resolved,
				OldIntegrity: be.Integrity, NewIntegrity: he.Integrity,
			})
		}
	}
	return added, changed, nil
}

// LockfileIntegrity flags an existing dependency whose resolved tarball or integrity
// changed without (necessarily) a version bump — a lockfile-poisoning indicator.
func LockfileIntegrity(c LockChange) verdict.Signal {
	return verdict.Signal{
		Check:   verdict.RuleLockfileIntegrity,
		Level:   verdict.LevelBlock,
		Message: "existing dependency " + c.Name + " had its resolved URL/integrity changed in the lockfile — possible lockfile poisoning",
	}
}
```

- [ ] **Step 4: Implement `internal/check/maintainer.go`**
```go
package check

import "github.com/tiagosilva07/invoke-guard/internal/verdict"

// MaintainerChange flags when the publishing maintainer set gained a new account
// versus a known-good baseline — an account-takeover / handoff signal.
func MaintainerChange(baseline, current []string) verdict.Signal {
	known := map[string]bool{}
	for _, m := range baseline {
		known[m] = true
	}
	for _, m := range current {
		if !known[m] {
			return verdict.Signal{
				Check:   verdict.RuleMaintainerChange,
				Level:   verdict.LevelWarn,
				Message: "a new maintainer (" + m + ") now publishes this package — verify it is not an account takeover",
			}
		}
	}
	return verdict.Signal{Check: verdict.RuleMaintainerChange, Level: verdict.LevelInfo}
}
```

- [ ] **Step 5: Run tests (PASS) + commit**
Run: `cd internal/check && go test ./...`
Expected: PASS.
```bash
git add internal/check/lockfile.go internal/check/maintainer.go internal/check/lockfile_test.go
git commit -m "feat(check): lockfile diff/integrity + maintainer-change signals"
```

---

## Task 14: `scan` PR-gate command + GitHub Action

**Files:** Modify `cmd/invoke-guard/main.go` (replace the `cmdScan` stub); Create `.github/actions/guard/action.yml`, `cmd/invoke-guard/scan_test.go`.

- [ ] **Step 1: Write the failing test** — `cmd/invoke-guard/scan_test.go`
```go
package main

import "testing"

func TestScanWorstExit(t *testing.T) {
	// helper that reduces a set of verdict strings + strict to an exit code
	if scanExit([]string{"SAFE", "WARN"}, false) != 0 {
		t.Error("safe+warn non-strict should be 0")
	}
	if scanExit([]string{"SAFE", "WARN"}, true) == 0 {
		t.Error("warn strict should be non-zero")
	}
	if scanExit([]string{"BLOCK"}, false) == 0 {
		t.Error("block should be non-zero")
	}
}
```

- [ ] **Step 2: Run to verify it fails**
Run: `cd cmd/invoke-guard && go test -run TestScanWorst ./...`
Expected: FAIL — undefined `scanExit`.

- [ ] **Step 3: Replace the `cmdScan` stub in `cmd/invoke-guard/main.go`**
```go
// cmdScan vets the dependencies a PR ADDS or CHANGES, by diffing the lockfile
// against a base. Only newly added/changed deps are checked, so it's fast and
// doesn't re-flag the whole tree. Reads base + head lockfiles from --base/--head
// (paths); defaults head to ./package-lock.json.
func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	basePath := fs.String("base", "", "base lockfile (e.g. the target branch's package-lock.json)")
	headPath := fs.String("head", "package-lock.json", "head lockfile")
	asJSON := fs.Bool("json", false, "JSON output")
	asSARIF := fs.Bool("sarif", false, "SARIF output")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	head, err := os.ReadFile(*headPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read head lockfile:", err)
		return 2
	}
	var base []byte
	if *basePath != "" {
		if base, err = os.ReadFile(*basePath); err != nil {
			fmt.Fprintln(os.Stderr, "read base lockfile:", err)
			return 2
		}
	} else {
		base = []byte(`{"packages":{}}`) // no base → treat all as added
	}
	added, changed, err := check.DiffLockfiles(base, head)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse lockfiles:", err)
		return 2
	}
	orch, err := check.NewNPM(".", loadPopular())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var results []verdict.Result
	for _, a := range added {
		results = append(results, orch.Check(context.Background(), a.Name, a.Version))
	}
	for _, c := range changed {
		r := verdict.Decide("npm", c.Name, c.NewIntegrity, []verdict.Signal{check.LockfileIntegrity(c)})
		results = append(results, r)
	}
	reporterFor(*asJSON, *asSARIF).Report(results)
	var verdicts []string
	for _, r := range results {
		verdicts = append(verdicts, r.VerdictStr)
	}
	return scanExit(verdicts, *strict)
}

func scanExit(verdicts []string, strict bool) int {
	worst := 0
	for _, v := range verdicts {
		if c := exitForVerdict(v, strict); c > worst {
			worst = c
		}
	}
	return worst
}
```

- [ ] **Step 4: Create the GitHub Action** — `.github/actions/guard/action.yml`
```yaml
name: Invoke Guard
description: Vet dependencies a PR adds or changes, before they reach main.
inputs:
  strict:
    description: Treat warnings as failures
    default: "true"
runs:
  using: composite
  steps:
    - shell: bash
      run: |
        set -euo pipefail
        git fetch origin "${{ github.base_ref }}" --depth=1 || true
        git show "origin/${{ github.base_ref }}:package-lock.json" > /tmp/base-lock.json 2>/dev/null || echo '{"packages":{}}' > /tmp/base-lock.json
        STRICT=""
        [ "${{ inputs.strict }}" = "true" ] && STRICT="--strict"
        invoke-guard scan --base /tmp/base-lock.json --head package-lock.json --sarif $STRICT > guard.sarif || EXIT=$?
        cat guard.sarif
        exit "${EXIT:-0}"
```

- [ ] **Step 5: Build + run tests (PASS) + commit**
Run: `go build ./... && cd cmd/invoke-guard && go test ./...`
Expected: builds; PASS.
```bash
git add cmd/invoke-guard/main.go cmd/invoke-guard/scan_test.go .github/actions/guard/action.yml
git commit -m "feat(cli): scan PR-gate (lockfile diff) + composite GitHub Action"
```

---

## Task 15: Popular-list data + refresh script + loadPopular

**Files:** Create `data/popular-npm.json`, `scripts/refresh-popular.sh`; Modify `cmd/invoke-guard/main.go` (`loadPopular`); Create `internal/data/embed.go`.

- [ ] **Step 1: Create a seed `data/popular-npm.json`** (a small committed seed; the script refreshes it to ~2000). Seed with a representative set:
```json
["react","lodash","express","chalk","request","axios","commander","react-dom","debug","next","vue","typescript","webpack","eslint","jest","moment","uuid","dotenv","cors","body-parser"]
```

- [ ] **Step 2: Create `scripts/refresh-popular.sh`** (documents how the list is regenerated; run manually, output committed)
```bash
#!/usr/bin/env bash
# Refresh data/popular-npm.json with the most-depended-upon npm packages.
# Uses the public npm search API (read-only). Commit the result.
set -euo pipefail
out=data/popular-npm.json
tmp=$(mktemp)
echo "[" > "$tmp"
first=1
for offset in $(seq 0 250 1750); do
  curl -fsS "https://registry.npmjs.org/-/v1/search?text=boost-exact:false&popularity=1.0&size=250&from=${offset}" \
    | python3 -c 'import sys,json;[print(o["package"]["name"]) for o in json.load(sys.stdin)["objects"]]'
done | sort -u | while read -r name; do
  [ $first -eq 1 ] && first=0 || echo "," >> "$tmp"
  printf '%s' "$(python3 -c "import json,sys;print(json.dumps(sys.argv[1]))" "$name")" >> "$tmp"
done
echo "]" >> "$tmp"
mv "$tmp" "$out"
echo "wrote $(python3 -c 'import json;print(len(json.load(open("data/popular-npm.json"))))') names to $out"
```
Make it executable: `chmod +x scripts/refresh-popular.sh`.

- [ ] **Step 3: Embed the data** — `internal/data/embed.go`
```go
// Package data embeds the bundled popular-package lists so the binary is fully
// self-contained (no runtime file dependency).
package data

import (
	_ "embed"
	"encoding/json"
)

//go:embed popular-npm.json
var popularNPMRaw []byte

// PopularNPM returns the bundled top-npm names.
func PopularNPM() []string {
	var out []string
	_ = json.Unmarshal(popularNPMRaw, &out)
	return out
}
```
Move the JSON so the embed path resolves: place `popular-npm.json` at `internal/data/popular-npm.json` (the `//go:embed` is relative to the package dir). Update Step 1's path accordingly and keep `data/` only for the human-facing copy if desired — simplest: keep ONE copy at `internal/data/popular-npm.json`.

- [ ] **Step 4: Wire `loadPopular`** in `cmd/invoke-guard/main.go` — replace the stub:
```go
func loadPopular() []string { return data.PopularNPM() }
```
And add the import `"github.com/tiagosilva07/invoke-guard/internal/data"`.

- [ ] **Step 5: Add a test** — `internal/data/embed_test.go`
```go
package data

import "testing"

func TestPopularNPMNonEmpty(t *testing.T) {
	if len(PopularNPM()) < 10 {
		t.Fatalf("expected a seed popular list, got %d", len(PopularNPM()))
	}
}
```

- [ ] **Step 6: Build + test (PASS) + commit**
Run: `go build ./... && go test ./...`
Expected: builds; all PASS.
```bash
git add internal/data scripts/refresh-popular.sh cmd/invoke-guard/main.go
git commit -m "feat(data): embed seed popular-npm list + refresh script"
```

---

## Task 16: Docs — README, CONTRIBUTING, INTEGRATION-INVOKE, SCHEMA

**Files:** Overwrite `README.md`; Create `CONTRIBUTING.md`, `docs/INTEGRATION-INVOKE.md`, `docs/SCHEMA.md`.

- [ ] **Step 1: Write `README.md`** — full version: what it is + why; install (`go install github.com/tiagosilva07/invoke-guard/cmd/invoke-guard@latest` and the signed-release download); quickstart (`check`/`install`/`allow`/`scan` with the example outputs from the spec); how the checks work; the three verdicts; using it with AI agents (today: run installs via `invoke-guard install`; roadmap: MCP/hook); using it in CI (the Action + `--strict`/`--sarif`); the **privacy promise** (only public package names you query ever leave the machine); the **OSS promise** (individual + single-repo free forever; paid = data + org services); and the roadmap table from spec §11.

- [ ] **Step 2: Write `CONTRIBUTING.md`** — build (`go build ./...`), test (`go test ./...`), the stdlib-only rule, how to add a denylist entry (PR to `internal/intel/denylist.go`), how to refresh the popular list, and the security stance (report vulns privately; this is a security tool — command-injection-safety and SSRF-allowlist invariants must never regress).

- [ ] **Step 3: Write `docs/SCHEMA.md`** — document the `--json` schema (`schemaVersion="1.0"`, the `results[]` object with every field from `verdict.Result` and `verdict.Signal`), with an example, and the stability promise (additive changes only within a major schemaVersion).

- [ ] **Step 4: Write `docs/INTEGRATION-INVOKE.md`**
```markdown
# Integrating Invoke Guard with the Invoke platform

Guard runs locally and in CI with no backend. Its results can flow into the Invoke
supply-chain platform for org-wide visibility and compliance mapping.

## Free path — SARIF (works today, no platform changes)

`invoke-guard scan --sarif > guard.sarif` emits SARIF 2.1.0 whose results match
exactly what the Invoke platform's SARIF importer reads:

| SARIF field | Value |
|---|---|
| `runs[].tool.driver.name` | `invoke-guard` |
| `results[].ruleId` | the check: `nonexistent`, `typosquat`, `known-malware`, `new-and-unused`, `lockfile-integrity`, `maintainer-change` |
| `results[].level` | `error` (BLOCK) / `warning` (WARN) / `note` (info) |
| `results[].message.text` | `name@version: <plain-language reason>` |

The platform maps `error→High`, `warning→Medium`, `note→Low`. Upload `guard.sarif`
the same way the platform's own scanners publish SARIF — Guard findings then appear
in the project's compliance/findings view, mapped to supply-chain controls.

## JSON path — tooling

`--json` emits the versioned schema in `SCHEMA.md` for custom integrations/agents.

## Paid path (roadmap) — native push

A future `--report invoke` pushes results directly to an Invoke org project
(authenticated), adding the dashboard, org policy, curated-feed verdicts, and
compliance reporting. Reserved on the same Reporter seam; the SARIF/JSON paths stay
free forever.
```

- [ ] **Step 5: Commit**
```bash
git add README.md CONTRIBUTING.md docs/INTEGRATION-INVOKE.md docs/SCHEMA.md
git commit -m "docs: README, CONTRIBUTING, platform-integration + result schema"
```

---

## Task 17: CI workflow (SHA-pinned)

**Files:** Create `.github/workflows/ci.yml`.

- [ ] **Step 1: Write `.github/workflows/ci.yml`** (resolve each action SHA via `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` at implementation time — do NOT copy SHAs from memory)
```yaml
name: CI
on:
  push: { branches: [develop, main] }
  pull_request: { branches: [develop, main] }
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@<sha>   # pin: actions/checkout@v4
      - uses: actions/setup-go@<sha>   # pin: actions/setup-go@v5
        with: { go-version: "1.23" }
      - run: gofmt -l . | tee /dev/stderr | (! read)   # fail if any file unformatted
      - run: go vet ./...
      - run: go build ./...
      - run: go test -race -count=1 ./...
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
      - run: go test -run x -fuzz FuzzDamerau -fuzztime 20s ./internal/check/
```

- [ ] **Step 2: Validate locally + commit**
Run: `python -c "import yaml;yaml.safe_load(open('.github/workflows/ci.yml'));print('ok')"`
Expected: `ok` (the `<sha>` placeholders are replaced with real pinned SHAs during implementation).
```bash
git add .github/workflows/ci.yml
git commit -m "ci: build/vet/test/govulncheck/fuzz (SHA-pinned actions)"
```

---

## Task 18: Release workflow — SLSA L3 provenance + cosign + SBOM

**Files:** Create `.github/workflows/release.yml`.

- [ ] **Step 1: Write `.github/workflows/release.yml`** (resolve all action SHAs via `gh api` at implementation time; mirror the Invoke platform's hardened release)
```yaml
name: Release
on:
  push: { tags: ["v*"] }
permissions: {}
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write       # create release + assets
      id-token: write        # cosign + provenance OIDC
      attestations: write    # SLSA build provenance
    steps:
      - uses: actions/checkout@<sha>   # pin: actions/checkout@v4
      - uses: actions/setup-go@<sha>   # pin: actions/setup-go@v5
        with: { go-version: "1.23" }
      - name: Build all targets (CGO-free static)
        run: |
          set -euo pipefail
          mkdir -p dist
          VERSION="${GITHUB_REF_NAME}"
          for os in linux darwin windows; do
            for arch in amd64 arm64; do
              ext=""; [ "$os" = windows ] && ext=".exe"
              CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
                -ldflags "-s -w -X main.version=${VERSION}" \
                -o "dist/invoke-guard-${os}-${arch}${ext}" ./cmd/invoke-guard
            done
          done
          cd dist && sha256sum invoke-guard-* > checksums.txt && cat checksums.txt
      - name: SLSA build provenance
        uses: actions/attest-build-provenance@<sha>   # pin: actions/attest-build-provenance@v2
        with: { subject-path: 'dist/invoke-guard-*' }
      - name: SBOM
        uses: anchore/sbom-action@<sha>   # pin: anchore/sbom-action@v0
        with: { path: ., format: spdx-json, output-file: dist/invoke-guard.spdx.json, upload-artifact: false, upload-release-assets: false }
      - name: Install cosign
        uses: sigstore/cosign-installer@<sha>   # pin: sigstore/cosign-installer@v3
      - name: Sign (keyless)
        run: cd dist && for f in invoke-guard-* checksums.txt invoke-guard.spdx.json; do cosign sign-blob --yes --bundle "${f}.cosign.bundle" "$f"; done
      - name: Release
        uses: softprops/action-gh-release@<sha>   # pin: softprops/action-gh-release@v2
        with:
          files: |
            dist/invoke-guard-*
            dist/checksums.txt
            dist/*.cosign.bundle
            dist/invoke-guard.spdx.json
          generate_release_notes: true
          prerelease: ${{ contains(github.ref_name, '-') }}
```

- [ ] **Step 2: Validate locally + commit**
Run: `python -c "import yaml;yaml.safe_load(open('.github/workflows/release.yml'));print('ok')"`
Expected: `ok`.
```bash
git add .github/workflows/release.yml
git commit -m "ci(release): SLSA L3 provenance + cosign + SBOM + checksums"
```

---

## Self-review notes (for the executor)

- **Spec coverage:** verdict engine (T2), seams (T3), hardened HTTP/SSRF (T4, +command-injection-safe install in T5/T12), npm provider (T5), four checks (T6 typosquat, T7 existence+popularity, T8 known-bad), multi-contributor checks (T13), policy (T9), reporters json/sarif/text (T10), orchestrator (T11), CLI check/install/allow (T12), scan PR-gate + Action (T14), popular data (T15), docs incl. platform integration + schema (T16), CI + SLSA L3 release (T17/T18). ✅
- **Type consistency:** `verdict.Signal{Check,Level,Message,Suggest}`, `verdict.Result`, `seam.Metadata/Advisory/Decision/InstallOpts`, the four interfaces, and the `Rule*` constants are defined in T2/T3 and used verbatim thereafter. SARIF ruleIds == `Rule*` values == check names (one vocabulary).
- **Placeholders:** the only intentional ones are the action `<sha>` pins in T17/T18 — fetched via `gh api` at implementation time per supply-chain rules (never from memory), and the module path `github.com/tiagosilva07/invoke-guard` (rename once if it lands under an org).
- **Open questions deferred to impl (spec §13):** typosquat thresholds are constants tuned in T6's tests; popular-list sourcing is T15's script; lockfile scope is npm v2/v3 `packages` map (T13); CLI uses stdlib `flag` (no framework).
- **NOT in v1 (per spec §2/§11):** MCP, shell hook, PyPI/crates, behavioral check, paid providers — the seams (T3) make each an additive drop-in.
