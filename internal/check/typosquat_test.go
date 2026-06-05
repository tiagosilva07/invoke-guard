package check

import (
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestTyposquat(t *testing.T) {
	popular := []string{"request", "express", "lodash", "react"}
	// queried name, its own weekly downloads, want level, want suggest
	cases := []struct {
		name    string
		loads   int
		level   verdict.Level
		suggest string
	}{
		{"express", 5_000_000, verdict.LevelInfo, ""},    // is itself popular → no flag
		{"reqeust", 3, verdict.LevelBlock, "request"},    // dist 1 + near-zero downloads → BLOCK
		{"requests", 5000, verdict.LevelWarn, "request"}, // dist 1 but actually USED → WARN, not BLOCK
		{"totally-unrelated", 5, verdict.LevelInfo, ""},  // far from all → nothing
	}
	for _, c := range cases {
		s := Typosquat(c.name, c.loads, popular)
		if s.Level != c.level || s.Suggest != c.suggest {
			t.Errorf("%q: got level=%v suggest=%q want level=%v suggest=%q", c.name, s.Level, s.Suggest, c.level, c.suggest)
		}
	}
}
