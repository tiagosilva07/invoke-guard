package pypi

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
