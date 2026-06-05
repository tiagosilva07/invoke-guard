package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func checkPackageTool() map[string]any {
	return map[string]any{
		"name":        "check_package",
		"description": "Vet a package for typosquats, known-malware, hallucinated names, and supply-chain risk BEFORE installing it. Returns SAFE, WARN, or BLOCK with reasons. Call this before running any package install.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name":      map[string]any{"type": "string", "description": "package name to check"},
				"version":   map[string]any{"type": "string", "description": "optional; defaults to the latest published version"},
				"ecosystem": map[string]any{"type": "string", "enum": []string{"npm", "pypi", "crates"}, "default": "npm"},
			},
			"required": []string{"name"},
		},
	}
}

func (s *Server) toolsCall(params json.RawMessage) map[string]any {
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Ecosystem string `json:"ecosystem"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name != "check_package" {
		return toolError("unknown tool or bad arguments")
	}
	if strings.TrimSpace(p.Arguments.Name) == "" {
		return toolError("missing required argument: name")
	}
	eco := p.Arguments.Ecosystem
	if eco == "" {
		eco = "npm"
	}
	checker, err := s.Resolve(eco)
	if err != nil {
		return toolError(err.Error())
	}
	res := checker.Check(context.Background(), p.Arguments.Name, p.Arguments.Version)
	structured, _ := json.Marshal(res)
	text := renderForAgent(res) + "\n\n" + string(structured)
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
		"isError": false, // a SAFE/WARN/BLOCK verdict is a valid result, never a tool error
	}
}

func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": "error: " + msg}},
		"isError": true,
	}
}

// renderForAgent produces a plain-language summary an agent can act on.
func renderForAgent(r verdict.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s@%s", r.VerdictStr, r.Name, r.Version)
	for _, s := range r.Signals {
		if s.Level == verdict.LevelInfo || s.Message == "" {
			continue
		}
		fmt.Fprintf(&b, "\n  - %s", s.Message)
	}
	if r.Suggestion != "" {
		fmt.Fprintf(&b, "\n  did you mean: %s", r.Suggestion)
	}
	switch r.Verdict {
	case verdict.Block:
		b.WriteString("\n\nRECOMMENDATION: do NOT install this package.")
	case verdict.Warn:
		b.WriteString("\n\nRECOMMENDATION: review carefully before installing.")
	default:
		b.WriteString("\n\nRECOMMENDATION: safe to install.")
	}
	return b.String()
}
