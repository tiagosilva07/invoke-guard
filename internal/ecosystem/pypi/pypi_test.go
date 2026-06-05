package pypi

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
	p := New(httpx.New([]string{host}), []string{"requests"})
	p.registryBase = srv.URL
	p.statsBase = srv.URL
	return p
}

func TestValidateName(t *testing.T) {
	p := New(nil, nil)
	for _, ok := range []string{"requests", "Flask", "python-dateutil", "zope.interface"} {
		if err := p.ValidateName(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"foo;rm", "../x", "-bad", "", "a b"} {
		if err := p.ValidateName(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestNormalize(t *testing.T) {
	if normalize("Flask_Cors.Ext") != "flask-cors-ext" {
		t.Errorf("normalize wrong: %s", normalize("Flask_Cors.Ext"))
	}
}

func TestExistsMetadata(t *testing.T) {
	p := newTestProvider(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/recent"):
			w.Write([]byte(`{"data":{"last_week":1234567}}`))
		case strings.Contains(r.URL.Path, "/pypi/requests/json"):
			w.Write([]byte(`{"info":{"version":"2.31.0","project_urls":{"Source":"https://github.com/psf/requests"}},"releases":{"2.31.0":[{"upload_time_iso_8601":"2023-05-22T00:00:00Z"}]}}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	ctx := context.Background()
	ok, err := p.Exists(ctx, "requests", "")
	if err != nil || !ok {
		t.Fatalf("requests should exist: %v %v", ok, err)
	}
	md, err := p.Metadata(ctx, "requests")
	if err != nil || md.Latest != "2.31.0" || md.WeeklyLoads != 1234567 {
		t.Fatalf("metadata wrong: %+v err=%v", md, err)
	}
	miss, _ := p.Exists(ctx, "nope-xyz-123", "")
	if miss {
		t.Fatal("nonexistent reported existing")
	}
}

func TestPyPIInstallCode(t *testing.T) {
	var sdistURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".tar.gz"):
			w.Write(pyTarGz(t))
		case strings.Contains(r.URL.Path, "/pypi/evil/json"):
			w.Write([]byte(`{"info":{"version":"1.0"},"urls":[{"packagetype":"sdist","url":"` + sdistURL + `"}]}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	sdistURL = srv.URL + "/packages/evil-1.0.tar.gz"
	host := strings.TrimPrefix(srv.URL, "http://")
	p := New(httpx.New([]string{host}), nil)
	p.registryBase = srv.URL
	files, err := p.InstallCode(context.Background(), "evil", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["evil-1.0/setup.py"]; !ok {
		t.Fatalf("expected setup.py: %v", files)
	}
	// wheel-only → empty
	p2 := New(httpx.New([]string{host}), nil)
	p2.registryBase = srv.URL
	// (a name whose json has no sdist would return empty; covered by analyzer Info)
}

// TestPyPIInstallCodeVersionPinned proves a pinned version analyzes that
// version's sdist (via /pypi/<name>/<version>/json), not the latest release.
func TestPyPIInstallCodeVersionPinned(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "old.tar.gz"):
			w.Write(pyTarGzNamed(t, "evil-1.0/setup.py", "old"))
		case strings.HasSuffix(r.URL.Path, "new.tar.gz"):
			w.Write(pyTarGzNamed(t, "evil-2.0/setup.py", "new"))
		case strings.Contains(r.URL.Path, "/pypi/evil/1.0/json"):
			w.Write([]byte(`{"info":{"version":"1.0"},"urls":[{"packagetype":"sdist","url":"` + base + `/packages/old.tar.gz"}]}`))
		case strings.Contains(r.URL.Path, "/pypi/evil/json"):
			w.Write([]byte(`{"info":{"version":"2.0"},"urls":[{"packagetype":"sdist","url":"` + base + `/packages/new.tar.gz"}]}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	base = srv.URL
	host := strings.TrimPrefix(srv.URL, "http://")
	p := New(httpx.New([]string{host}), nil)
	p.registryBase = srv.URL
	files, err := p.InstallCode(context.Background(), "evil", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["evil-1.0/setup.py"]; !ok {
		t.Fatalf("expected the version-pinned 1.0 sdist, got: %v", files)
	}
	// A nonexistent pinned version → 404 → empty map (best-effort), not an error.
	empty, err := p.InstallCode(context.Background(), "evil", "9.9")
	if err != nil {
		t.Fatalf("missing version should degrade to empty, got err: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("missing version should be empty, got: %v", empty)
	}
}

func pyTarGz(t *testing.T) []byte {
	return pyTarGzNamed(t, "evil-1.0/setup.py", "import os; os.system('id')")
}

func pyTarGzNamed(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	gz.Close()
	return buf.Bytes()
}
