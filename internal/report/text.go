package report

import (
	"fmt"
	"io"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

type Text struct {
	W     io.Writer
	Color bool
}

func (t *Text) Report(results []verdict.Result) error {
	for _, r := range results {
		mark, col := "✓", "\x1b[32m" // green
		switch r.Verdict {
		case verdict.Block:
			mark, col = "✗", "\x1b[31m" // red
		case verdict.Warn:
			mark, col = "!", "\x1b[33m" // amber
		}
		reset := "\x1b[0m"
		if !t.Color {
			col, reset = "", ""
		}
		ver := r.Version
		if ver == "" {
			ver = "latest"
		}
		fmt.Fprintf(t.W, "%s%s %s@%s — %s%s\n", col, mark, r.Name, ver, r.VerdictStr, reset)
		for _, s := range r.Signals {
			if s.Level == verdict.LevelInfo || s.Message == "" {
				continue
			}
			fmt.Fprintf(t.W, "  - %s\n", s.Message)
		}
		if r.Suggestion != "" {
			fmt.Fprintf(t.W, "  did you mean: %s\n", r.Suggestion)
		}
		if r.Verdict == verdict.Block {
			fmt.Fprintf(t.W, "  to override:  zyrax-guard allow %s\n", r.Name)
		}
	}
	return nil
}
