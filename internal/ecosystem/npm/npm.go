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

	"github.com/tiagosilva07/zyrax-guard/internal/artifact"
	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
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
	Time struct {
		Created time.Time `json:"created"`
	} `json:"time"`
	Maintainers []struct {
		Name string `json:"name"`
	} `json:"maintainers"`
	Repository struct {
		URL string `json:"url"`
	} `json:"repository"`
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
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
		Latest:    pk.DistTags.Latest,
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

type tarballPackument struct {
	DistTags map[string]string `json:"dist-tags"`
	Versions map[string]struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	} `json:"versions"`
}

// InstallCode downloads the version's tarball and returns its extracted files
// (path->content) for static install-script analysis.
func (p *Provider) InstallCode(ctx context.Context, name, version string) (map[string]string, error) {
	if err := p.ValidateName(name); err != nil {
		return nil, err
	}
	var pk tarballPackument
	code, err := p.http.GetJSON(ctx, p.registryBase+"/"+name, &pk)
	if err != nil || code != 200 {
		return nil, err
	}
	if version == "" {
		version = pk.DistTags["latest"]
	}
	url := pk.Versions[version].Dist.Tarball
	if url == "" {
		return map[string]string{}, nil
	}
	_, b, err := p.http.GetBytes(ctx, url, 32<<20)
	if err != nil {
		return nil, err
	}
	return artifact.ExtractTarGz(b, artifact.DefaultLimits())
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
