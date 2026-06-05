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
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
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
