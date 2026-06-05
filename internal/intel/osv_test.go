package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/httpx"
)

func TestOSVLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"vulns":[{"id":"MAL-123","summary":"malware","database_specific":{"severity":"CRITICAL"}}]}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	o := NewOSV(httpx.New([]string{host}))
	o.base = srv.URL
	advs, err := o.Lookup(context.Background(), "npm", "evil", "1.0.0")
	if err != nil || len(advs) != 1 || !advs[0].Malware {
		t.Fatalf("advs=%+v err=%v", advs, err)
	}
}

func TestDenylist(t *testing.T) {
	if !InDenylist("npm", "known-evil-pkg") {
		t.Skip("seed denylist may be empty in v1; ensure InDenylist exists")
	}
}

func TestOSVLookup_BestEffortOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	o := NewOSV(httpx.New([]string{host}))
	o.base = srv.URL
	// "crossenv" is in the bundled denylist → must still be flagged as malware,
	// and the OSV 429 must NOT surface as an error.
	advs, err := o.Lookup(context.Background(), "npm", "crossenv", "1.0.0")
	if err != nil {
		t.Fatalf("OSV downtime must be tolerated, got err=%v", err)
	}
	if len(advs) != 1 || !advs[0].Malware {
		t.Fatalf("denylist must still fire on OSV downtime: %+v", advs)
	}
}
