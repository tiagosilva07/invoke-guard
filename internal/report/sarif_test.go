package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestSARIFShapeMatchesPlatform(t *testing.T) {
	res := []verdict.Result{{
		Ecosystem: "npm", Name: "reqeust", Version: "1.0.0", Verdict: verdict.Block, VerdictStr: "BLOCK",
		Signals: []verdict.Signal{{Check: verdict.RuleTyposquat, Level: verdict.LevelBlock, Message: "typo of request"}},
	}}
	var buf bytes.Buffer
	if err := (&SARIF{W: &buf}).Report(res); err != nil {
		t.Fatal(err)
	}
	// Must parse into the platform importer's expected shape.
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct{ Name string `json:"name"` } `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct{ Text string `json:"text"` } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("sarif not parseable: %v", err)
	}
	r := doc.Runs[0]
	if r.Tool.Driver.Name != "invoke-guard" {
		t.Errorf("driver name = %q", r.Tool.Driver.Name)
	}
	if len(r.Results) != 1 || r.Results[0].RuleID != "typosquat" || r.Results[0].Level != "error" {
		t.Errorf("result wrong: %+v", r.Results)
	}
	if r.Results[0].Message.Text == "" {
		t.Error("message text empty")
	}
}
