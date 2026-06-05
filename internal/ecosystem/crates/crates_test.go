package crates

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
	p := New(httpx.New([]string{host}), []string{"serde"})
	p.base = srv.URL
	return p
}

func TestValidateName(t *testing.T) {
	p := New(nil, nil)
	for _, ok := range []string{"serde", "serde_json", "rand-core", "log"} {
		if err := p.ValidateName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"foo;rm", "../x", "", "has space", "_leading", strings.Repeat("a", 65)} {
		if err := p.ValidateName(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExistsMetadataSendsUA(t *testing.T) {
	var ua string
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		if strings.Contains(r.URL.Path, "/crates/serde") {
			w.Write([]byte(`{"crate":{"newest_version":"1.0.197","repository":"https://github.com/serde-rs/serde","recent_downloads":98765432,"created_at":"2014-12-05T00:00:00Z"}}`))
			return
		}
		http.Error(w, "nf", http.StatusNotFound)
	}))
	ctx := context.Background()
	md, err := p.Metadata(ctx, "serde")
	if err != nil || md.Latest != "1.0.197" || md.WeeklyLoads != 98765432 {
		t.Fatalf("metadata wrong: %+v err=%v", md, err)
	}
	if !strings.Contains(ua, "invoke-guard") {
		t.Errorf("crates.io needs a User-Agent; got %q", ua)
	}
	miss, _ := p.Exists(ctx, "nope-xyz-123", "")
	if miss {
		t.Fatal("nonexistent reported existing")
	}
}
