// Package pypi implements seam.Ecosystem for the public PyPI registry. Metadata is
// read-only JSON; installs use an argument-array exec (never a shell).
package pypi

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/artifact"
	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

const (
	RegistryHost = "pypi.org"
	StatsHost    = "pypistats.org"
	FilesHost    = "files.pythonhosted.org"
)

// PEP 503: a valid name matches this; normalized form lowercases and collapses ._- to -.
var nameRe = regexp.MustCompile(`^([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9._-]*[A-Za-z0-9])$`)
var sepRe = regexp.MustCompile(`[-_.]+`)

// safeVersion gates a version before it goes into a registry URL path. PEP 440
// versions use only this character set; anything else (notably '/') is rejected
// so it cannot inject path segments — we fall back to the latest release instead.
var safeVersion = regexp.MustCompile(`^[A-Za-z0-9._+!-]+$`)

func normalize(name string) string {
	return sepRe.ReplaceAllString(strings.ToLower(name), "-")
}

type Provider struct {
	http         *httpx.Client
	popular      []string
	registryBase string
	statsBase    string
}

func New(client *httpx.Client, popular []string) *Provider {
	return &Provider{
		http:         client,
		popular:      popular,
		registryBase: "https://" + RegistryHost,
		statsBase:    "https://" + StatsHost,
	}
}

func (p *Provider) Name() string          { return "pypi" }
func (p *Provider) PopularList() []string { return p.popular }

func (p *Provider) ValidateName(name string) error {
	if len(name) == 0 || len(name) > 214 {
		return fmt.Errorf("invalid pypi name length")
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("%q is not a legal PyPI package name", name)
	}
	return nil
}

func (p *Provider) Exists(ctx context.Context, name, _ string) (bool, error) {
	if err := p.ValidateName(name); err != nil {
		return false, err
	}
	code, err := p.http.GetJSON(ctx, p.registryBase+"/pypi/"+normalize(name)+"/json", nil)
	if err != nil {
		return false, err
	}
	return code == 200, nil
}

type pypiJSON struct {
	Info struct {
		Version     string            `json:"version"`
		ProjectURLs map[string]string `json:"project_urls"`
		HomePage    string            `json:"home_page"`
	} `json:"info"`
	Releases map[string][]struct {
		UploadTime time.Time `json:"upload_time_iso_8601"`
	} `json:"releases"`
}

type statsJSON struct {
	Data struct {
		LastWeek int `json:"last_week"`
	} `json:"data"`
}

func (p *Provider) Metadata(ctx context.Context, name string) (seam.Metadata, error) {
	if err := p.ValidateName(name); err != nil {
		return seam.Metadata{}, err
	}
	n := normalize(name)
	var j pypiJSON
	code, err := p.http.GetJSON(ctx, p.registryBase+"/pypi/"+n+"/json", &j)
	if err != nil {
		return seam.Metadata{}, err
	}
	if code != 200 {
		return seam.Metadata{Exists: false}, nil
	}
	md := seam.Metadata{Exists: true, Latest: j.Info.Version}
	if u := pickRepo(j.Info.ProjectURLs, j.Info.HomePage); u != "" {
		md.RepoURL = u
	}
	if rels := j.Releases[j.Info.Version]; len(rels) > 0 {
		md.Published = rels[0].UploadTime
	}
	var s statsJSON
	if _, err := p.http.GetJSON(ctx, p.statsBase+"/api/packages/"+n+"/recent", &s); err == nil {
		md.WeeklyLoads = s.Data.LastWeek
	}
	return md, nil
}

func pickRepo(urls map[string]string, home string) string {
	for _, k := range []string{"Source", "Source Code", "Repository", "Code"} {
		if v := urls[k]; v != "" {
			return v
		}
	}
	return home
}

type pypiURLs struct {
	URLs []struct {
		PackageType string `json:"packagetype"`
		URL         string `json:"url"`
	} `json:"urls"`
}

// InstallCode downloads the sdist (if any) and returns its files. When version
// is given (and well-formed) it fetches that release's artifacts via the
// per-version endpoint; otherwise it falls back to the latest release. Wheel-only
// packages, missing versions, and 404s have no install-time code → an empty map
// (the analyzer reports Info) — never an error, keeping deep checks best-effort.
func (p *Provider) InstallCode(ctx context.Context, name, version string) (map[string]string, error) {
	if err := p.ValidateName(name); err != nil {
		return nil, err
	}
	url := p.registryBase + "/pypi/" + normalize(name) + "/json"
	if version != "" && safeVersion.MatchString(version) {
		url = p.registryBase + "/pypi/" + normalize(name) + "/" + version + "/json"
	}
	var u pypiURLs
	code, err := p.http.GetJSON(ctx, url, &u)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return map[string]string{}, nil // not found / no such release → nothing to inspect
	}
	var sdist string
	for _, x := range u.URLs {
		if x.PackageType == "sdist" {
			sdist = x.URL
			break
		}
	}
	if sdist == "" {
		return map[string]string{}, nil // wheel-only
	}
	_, b, err := p.http.GetBytes(ctx, sdist, 32<<20)
	if err != nil {
		return nil, err
	}
	return artifact.ExtractTarGz(b, artifact.DefaultLimits())
}

// Install runs `pip install <names>` with names as ARRAY args (never a shell).
// IgnoreScripts has no pip equivalent and is ignored.
func (p *Provider) Install(ctx context.Context, names []string, _ seam.InstallOpts) error {
	for _, n := range names {
		if err := p.ValidateName(n); err != nil {
			return err
		}
	}
	args := append([]string{"install"}, names...)
	cmd := exec.CommandContext(ctx, "pip", args...)
	cmd.Stdout, cmd.Stderr = stdout(), stderr()
	return cmd.Run()
}
