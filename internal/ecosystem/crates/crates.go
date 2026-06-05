// Package crates implements seam.Ecosystem for crates.io. crates.io returns
// existence, version, and recent_downloads in one call and requires a User-Agent
// (the httpx client sends one).
package crates

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/httpx"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
)

const Host = "crates.io"

// crates names: alphanumeric, _ and -, must start with a letter, max 64.
var nameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`)

type Provider struct {
	http    *httpx.Client
	popular []string
	base    string
}

func New(client *httpx.Client, popular []string) *Provider {
	return &Provider{http: client, popular: popular, base: "https://" + Host}
}

func (p *Provider) Name() string          { return "crates" }
func (p *Provider) PopularList() []string { return p.popular }

func (p *Provider) ValidateName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return fmt.Errorf("invalid crate name length")
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%q is not a legal crate name", name)
	}
	return nil
}

func (p *Provider) Exists(ctx context.Context, name, _ string) (bool, error) {
	if err := p.ValidateName(name); err != nil {
		return false, err
	}
	code, err := p.http.GetJSON(ctx, p.base+"/api/v1/crates/"+name, nil)
	if err != nil {
		return false, err
	}
	return code == 200, nil
}

type cratesJSON struct {
	Crate struct {
		NewestVersion   string    `json:"newest_version"`
		MaxVersion      string    `json:"max_version"`
		Repository      string    `json:"repository"`
		RecentDownloads int       `json:"recent_downloads"`
		CreatedAt       time.Time `json:"created_at"`
	} `json:"crate"`
}

func (p *Provider) Metadata(ctx context.Context, name string) (seam.Metadata, error) {
	if err := p.ValidateName(name); err != nil {
		return seam.Metadata{}, err
	}
	var j cratesJSON
	code, err := p.http.GetJSON(ctx, p.base+"/api/v1/crates/"+name, &j)
	if err != nil {
		return seam.Metadata{}, err
	}
	if code != 200 {
		return seam.Metadata{Exists: false}, nil
	}
	latest := j.Crate.NewestVersion
	if latest == "" {
		latest = j.Crate.MaxVersion
	}
	return seam.Metadata{
		Exists:      true,
		Latest:      latest,
		RepoURL:     j.Crate.Repository,
		WeeklyLoads: j.Crate.RecentDownloads,
		Published:   j.Crate.CreatedAt,
	}, nil
}

// Install runs `cargo add <names>` (the add-a-dependency analog) with array args.
func (p *Provider) Install(ctx context.Context, names []string, _ seam.InstallOpts) error {
	for _, n := range names {
		if err := p.ValidateName(n); err != nil {
			return err
		}
	}
	args := append([]string{"add"}, names...)
	cmd := exec.CommandContext(ctx, "cargo", args...)
	cmd.Stdout, cmd.Stderr = stdout(), stderr()
	return cmd.Run()
}
