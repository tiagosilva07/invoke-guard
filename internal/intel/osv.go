package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
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
		// OSV is a best-effort supplement; the bundled denylist is the
		// authoritative floor. Tolerate OSV downtime rather than failing the
		// whole check (known limitation: OSV-only malware is missed while OSV
		// is unreachable).
		return out, nil
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
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("OSV responded with status %d", code)
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
