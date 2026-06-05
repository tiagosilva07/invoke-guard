package check

import (
	"fmt"

	"github.com/tiagosilva07/zyrax-guard/internal/data"
	"github.com/tiagosilva07/zyrax-guard/internal/ecosystem/crates"
	"github.com/tiagosilva07/zyrax-guard/internal/ecosystem/npm"
	"github.com/tiagosilva07/zyrax-guard/internal/ecosystem/pypi"
	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/intel"
	"github.com/tiagosilva07/zyrax-guard/internal/policy"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

// New wires an orchestrator for the named ecosystem (npm, pypi, crates) with a
// hardened HTTP client allowlisting just that ecosystem's hosts + OSV, the bundled
// popular list, OSV intel, and the project-local policy.
func New(ecosystem, projectDir string) (*Orchestrator, error) {
	pol, err := policy.Load(projectDir)
	if err != nil {
		return nil, err
	}
	var (
		eco   seam.Ecosystem
		hosts []string
	)
	switch ecosystem {
	case "npm":
		hosts = []string{npm.RegistryHost, npm.DownloadsHost, intel.OSVHost}
		eco = npm.New(httpx.New(hosts), data.PopularNPM())
	case "pypi":
		hosts = []string{pypi.RegistryHost, pypi.StatsHost, pypi.FilesHost, intel.OSVHost}
		eco = pypi.New(httpx.New(hosts), data.PopularPyPI())
	case "crates":
		hosts = []string{crates.Host, crates.StaticHost, intel.OSVHost}
		eco = crates.New(httpx.New(hosts), data.PopularCrates())
	default:
		return nil, fmt.Errorf("unsupported ecosystem %q (use npm, pypi, or crates)", ecosystem)
	}
	// The intel client may talk to OSV for any ecosystem; build it on a client that
	// allows OSV (each provider's client above already includes intel.OSVHost).
	return &Orchestrator{
		Eco:    eco,
		Intel:  intel.NewOSV(httpx.New([]string{intel.OSVHost})),
		Policy: pol,
	}, nil
}

// NewNPM is kept for back-compat; it builds the npm orchestrator. The popular arg
// is ignored in favour of the bundled list (callers pass loadPopular()/nil).
func NewNPM(projectDir string, _ []string) (*Orchestrator, error) {
	return New("npm", projectDir)
}

var _ seam.Policy = (*policy.Local)(nil)
