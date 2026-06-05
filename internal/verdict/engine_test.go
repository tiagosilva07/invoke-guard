package verdict

import "testing"

func TestDecide(t *testing.T) {
	tests := []struct {
		name    string
		signals []Signal
		want    Verdict
		suggest string
	}{
		{"no signals is safe", nil, Safe, ""},
		{"info only is safe", []Signal{{Check: RuleNewAndUnused, Level: LevelInfo, Message: "new"}}, Safe, ""},
		{"a warn signal warns", []Signal{{Check: RuleNewAndUnused, Level: LevelWarn, Message: "new+unused"}}, Warn, ""},
		{"a block signal blocks", []Signal{{Check: RuleNonexistent, Level: LevelBlock, Message: "404"}}, Block, ""},
		{"block beats warn", []Signal{{Check: RuleNewAndUnused, Level: LevelWarn}, {Check: RuleKnownMalware, Level: LevelBlock}}, Block, ""},
		{"suggestion surfaces", []Signal{{Check: RuleTyposquat, Level: LevelBlock, Message: "typo", Suggest: "request"}}, Block, "request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide("npm", "pkg", "1.0.0", tc.signals)
			if got.Verdict != tc.want {
				t.Errorf("verdict = %v, want %v", got.Verdict, tc.want)
			}
			if got.Suggestion != tc.suggest {
				t.Errorf("suggestion = %q, want %q", got.Suggestion, tc.suggest)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	if Block.String() != "BLOCK" || Warn.String() != "WARN" || Safe.String() != "SAFE" {
		t.Fatal("verdict strings wrong")
	}
}
