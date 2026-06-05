package crates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
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
	if !strings.Contains(ua, "zyrax-guard") {
		t.Errorf("crates.io needs a User-Agent; got %q", ua)
	}
	miss, _ := p.Exists(ctx, "nope-xyz-123", "")
	if miss {
		t.Fatal("nonexistent reported existing")
	}
}

func TestCratesInstallCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/download") {
			w.Write(crTarGz(t))
			return
		}
		http.Error(w, "nf", http.StatusNotFound)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	p := New(httpx.New([]string{host}), nil)
	p.base = srv.URL
	files, err := p.InstallCode(context.Background(), "evil", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["evil-1.0.0/build.rs"]; !ok {
		t.Fatalf("expected build.rs: %v", files)
	}
}

func crTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := "fn main(){ let _ = reqwest::blocking::get(\"http://x\"); }"
	tw.WriteHeader(&tar.Header{Name: "evil-1.0.0/build.rs", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}
