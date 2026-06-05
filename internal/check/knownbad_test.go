package check

import (
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func TestKnownBad(t *testing.T) {
	if s := KnownBad([]seam.Advisory{{Malware: true, Summary: "malware"}}); s.Level != verdict.LevelBlock {
		t.Errorf("malware should BLOCK, got %v", s.Level)
	}
	if s := KnownBad([]seam.Advisory{{Severity: "high", Summary: "vuln"}}); s.Level != verdict.LevelBlock {
		t.Errorf("high severity should BLOCK, got %v", s.Level)
	}
	if s := KnownBad([]seam.Advisory{{Severity: "low", Summary: "minor"}}); s.Level != verdict.LevelWarn {
		t.Errorf("low severity should WARN, got %v", s.Level)
	}
	if s := KnownBad(nil); s.Level != verdict.LevelInfo {
		t.Errorf("no advisories should be info, got %v", s.Level)
	}
}
