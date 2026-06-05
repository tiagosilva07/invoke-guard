package policy

import (
	"path/filepath"
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
)

func TestLocalPolicyAllow(t *testing.T) {
	dir := t.TempDir()
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Decide("foo") != seam.Defer {
		t.Fatal("unknown package should Defer")
	}
	if err := p.Allow("foo"); err != nil {
		t.Fatal(err)
	}
	// reload from disk
	p2, _ := Load(dir)
	if p2.Decide("foo") != seam.ForceAllow {
		t.Fatal("allowed package should ForceAllow after reload")
	}
	if _, err := filepath.Rel(dir, p.path); err != nil {
		t.Fatal("policy file must live under the project dir")
	}
}
