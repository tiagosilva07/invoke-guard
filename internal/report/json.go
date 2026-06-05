package report

import (
	"encoding/json"
	"io"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

const SchemaVersion = "1.0"

type JSON struct{ W io.Writer }

func (j *JSON) Report(results []verdict.Result) error {
	if results == nil {
		results = []verdict.Result{}
	}
	doc := map[string]any{
		"schemaVersion": SchemaVersion,
		"results":       results,
	}
	enc := json.NewEncoder(j.W)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
