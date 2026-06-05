package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetJSON_AllowedHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	var out struct {
		OK bool `json:"ok"`
	}
	code, err := c.GetJSON(context.Background(), srv.URL, &out)
	if err != nil || code != 200 || !out.OK {
		t.Fatalf("code=%d err=%v out=%+v", code, err, out)
	}
}

func TestGetJSON_DisallowedHost(t *testing.T) {
	c := New([]string{"registry.npmjs.org"})
	_, err := c.GetJSON(context.Background(), "http://169.254.169.254/latest/meta-data", nil)
	if err == nil {
		t.Fatal("expected host-not-allowed error (SSRF guard)")
	}
}

func TestGetJSON_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	code, err := c.GetJSON(context.Background(), srv.URL, nil)
	if code != 404 || err != nil {
		t.Fatalf("want 404,nil got code=%d err=%v", code, err)
	}
}

func TestPostJSON_DisallowedHost(t *testing.T) {
	c := New([]string{"registry.npmjs.org"})
	req, _ := http.NewRequest(http.MethodPost, "http://169.254.169.254/latest/meta-data", nil)
	_, _, err := c.PostJSON(req)
	if err == nil {
		t.Fatal("expected host-not-allowed error (SSRF guard)")
	}
}

func TestGetJSON_SendsUserAgent(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New([]string{srv.Listener.Addr().String()})
	if _, err := c.GetJSON(context.Background(), srv.URL, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ua, "invoke-guard") {
		t.Errorf("User-Agent = %q, want it to contain invoke-guard", ua)
	}
}
