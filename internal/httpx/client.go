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

// UserAgent identifies Guard to registries (crates.io rejects requests without one).
const UserAgent = "invoke-guard (+https://github.com/tiagosilva07/invoke-guard)"

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

func isLoopback(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func schemeOK(u *url.URL) error {
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil // permit plaintext only to loopback (test servers)
	}
	return fmt.Errorf("only HTTPS is allowed (got scheme %q for host %q)", u.Scheme, u.Host)
}

// GetJSON GETs url and, on 200, decodes the body into out (may be nil to skip).
// Returns the HTTP status code. A non-2xx is not an error (callers branch on code);
// transport/SSRF problems are errors.
func (c *Client) GetJSON(ctx context.Context, rawurl string, out any) (int, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return 0, err
	}
	if err := schemeOK(u); err != nil {
		return 0, err
	}
	if !c.hostAllowed(u) {
		return 0, fmt.Errorf("host %q not in allowlist (SSRF guard)", u.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
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

// PostJSON sends an already-built POST request, enforcing the same host allowlist,
// and returns the status code + raw body (capped). For the few APIs (OSV) that
// require POST. Body must already be set on req.
func (c *Client) PostJSON(req *http.Request) (int, []byte, error) {
	if err := schemeOK(req.URL); err != nil {
		return 0, nil, err
	}
	if !c.hostAllowed(req.URL) {
		return 0, nil, fmt.Errorf("host %q not in allowlist (SSRF guard)", req.URL.Host)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UserAgent)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, raw, nil
}
