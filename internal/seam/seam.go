// Package seam defines the four interfaces that keep the verdict engine
// ecosystem- and business-agnostic: Ecosystem, ThreatIntel, Policy, Reporter.
// Alternative implementations can drop in behind these interfaces later.
package seam

import (
	"context"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// Metadata is the registry facts a check needs.
type Metadata struct {
	Published   time.Time
	WeeklyLoads int
	Maintainers []string // stable identifiers (e.g. npm usernames)
	RepoURL     string
	Exists      bool
	Latest      string // dist-tags latest version (the version a bare install resolves to)
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
	// InstallCode returns the package's install/build-time code files (path->content)
	// for static deep analysis. Empty map = no such code.
	InstallCode(ctx context.Context, name, version string) (map[string]string, error)
}

// ThreatIntel returns known-bad records (OSV plus a bundled denylist).
type ThreatIntel interface {
	Lookup(ctx context.Context, ecosystem, name, version string) ([]Advisory, error)
}

// Decision is a Policy outcome for a package.
type Decision int

const (
	Defer      Decision = iota // no opinion — let the checks decide
	ForceAllow                 // explicitly allowed — short-circuit to SAFE
	ForceDeny                  // explicitly denied — short-circuit to BLOCK
)

// Policy is the allow/deny source (the local committed policy file by default).
type Policy interface {
	Decide(name string) Decision
	Allow(name string) error // persist an allowlist entry
}

// Reporter renders results (text, json, or sarif).
type Reporter interface {
	Report(results []verdict.Result) error
}
