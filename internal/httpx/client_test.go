package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
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
