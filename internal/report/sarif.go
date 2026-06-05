// Package report renders verdict results. SARIF output matches the exact subset the
// Invoke platform's importer reads (tool.driver.name + results[].ruleId/level/message.text),
// so Guard findings ingest into the platform with no platform changes.
package report

import (
	"encoding/json"
	"io"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

type SARIF struct{ W io.Writer }

func levelString(l verdict.Level) string {
	switch l {
	case verdict.LevelBlock:
		return "error"
	case verdict.LevelWarn:
		return "warning"
	default:
		return "note"
	}
}

func (s *SARIF) Report(results []verdict.Result) error {
	type msg struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message msg    `json:"message"`
	}
	out := []result{}
	for _, r := range results {
		for _, sig := range r.Signals {
			if sig.Level == verdict.LevelInfo {
				continue // only surface what actually fired
			}
			out = append(out, result{
				RuleID:  sig.Check,
				Level:   levelString(sig.Level),
				Message: msg{Text: r.Name + "@" + r.Version + ": " + sig.Message},
			})
		}
	}
	doc := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "invoke-guard"}},
			"results": out,
		}},
	}
	enc := json.NewEncoder(s.W)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
