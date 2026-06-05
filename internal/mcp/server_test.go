package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

type fakeChecker struct{ res verdict.Result }

func (f fakeChecker) Check(_ context.Context, name, version string) verdict.Result {
	r := f.res
	r.Name, r.Version = name, version
	return r
}

// run feeds each input line through the server and returns the decoded JSON-RPC
// responses (notifications produce no response).
func run(t *testing.T, c Checker, lines ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var out strings.Builder
	srv := &Server{Version: "test", Resolve: func(string) (Checker, error) { return c, nil }}
	if err := srv.Serve(in, &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var resps []map[string]any
	sc := bufio.NewScanner(strings.NewReader(out.String()))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad response line %q: %v", sc.Text(), err)
		}
		resps = append(resps, m)
	}
	return resps
}

func TestToolsCallEcosystemRouted(t *testing.T) {
	var gotEco string
	srv := &Server{Version: "test", Resolve: func(eco string) (Checker, error) {
		gotEco = eco
		return fakeChecker{res: verdict.Result{Verdict: verdict.Safe, VerdictStr: "SAFE"}}, nil
	}}
	var out strings.Builder
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_package","arguments":{"name":"serde","ecosystem":"crates"}}}` + "\n")
	if err := srv.Serve(in, &out); err != nil {
		t.Fatal(err)
	}
	if gotEco != "crates" {
		t.Errorf("ecosystem routed = %q, want crates", gotEco)
	}
}

func TestInitializeAndToolsList(t *testing.T) {
	resps := run(t, fakeChecker{},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	)
	if len(resps) != 2 { // the notification yields no response
		t.Fatalf("want 2 responses, got %d: %+v", len(resps), resps)
	}
	init := resps[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-06-18" {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	if init["serverInfo"].(map[string]any)["name"] != "invoke-guard" {
		t.Errorf("serverInfo.name wrong: %v", init["serverInfo"])
	}
	tools := resps[1]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "check_package" {
		t.Errorf("tools/list wrong: %v", tools)
	}
}

func TestParseErrorAndUnknownMethod(t *testing.T) {
	resps := run(t, fakeChecker{},
		`not json`,
		`{"jsonrpc":"2.0","id":9,"method":"no/such"}`,
	)
	if len(resps) != 2 {
		t.Fatalf("want 2, got %d", len(resps))
	}
	if resps[0]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Errorf("parse error code wrong: %v", resps[0])
	}
	if resps[1]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Errorf("method-not-found code wrong: %v", resps[1])
	}
}

func TestToolsCallBlock(t *testing.T) {
	res := verdict.Result{
		Verdict: verdict.Block, VerdictStr: "BLOCK",
		Signals:    []verdict.Signal{{Check: verdict.RuleTyposquat, Level: verdict.LevelBlock, Message: "typo of request"}},
		Suggestion: "request",
	}
	resps := run(t, fakeChecker{res: res},
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_package","arguments":{"name":"reqeust"}}}`,
	)
	if len(resps) != 1 {
		t.Fatalf("want 1 response, got %d", len(resps))
	}
	result := resps[0]["result"].(map[string]any)
	if result["isError"] != false {
		t.Errorf("a BLOCK verdict must NOT be a tool error (isError): %v", result["isError"])
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "BLOCK") || !strings.Contains(text, "do NOT install") || !strings.Contains(text, "reqeust") {
		t.Errorf("text missing verdict/recommendation/name: %q", text)
	}
	if !strings.Contains(text, `"verdict":"BLOCK"`) {
		t.Errorf("text missing structured JSON: %q", text)
	}
}

func TestToolsCallMissingName(t *testing.T) {
	resps := run(t, fakeChecker{},
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"check_package","arguments":{}}}`,
	)
	result := resps[0]["result"].(map[string]any)
	if result["isError"] != true {
		t.Errorf("missing name should be a tool error")
	}
}
