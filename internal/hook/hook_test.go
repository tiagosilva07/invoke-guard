package hook

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSnippetStructure(t *testing.T) {
	for _, sh := range []string{"bash", "zsh", "powershell"} {
		s, err := Snippet(sh)
		if err != nil {
			t.Fatalf("%s: %v", sh, err)
		}
		// Routes the install verbs and never recurses into the wrapper.
		for _, want := range []string{"install", "add", "invoke-guard check"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s snippet missing %q", sh, want)
			}
		}
	}
	if _, err := Snippet("fish"); err == nil {
		t.Error("unknown shell should error")
	}
}

func TestBashSnippetGatesAndPassesThrough(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	s, err := Snippet("bash")
	if err != nil {
		t.Fatal(err)
	}
	// Stub `invoke-guard` (blocks "evil", allows others) and `command` is real.
	// Define a stub real npm by shadowing PATH lookup: we assert routing via echo.
	script := `
set -e
` + s + `
invoke-guard() { case "$2" in evil) echo "BLOCK"; return 1;; *) return 0;; esac; }
command() { shift; echo "REAL_NPM $*"; }   # stub the real npm call
# install of a safe pkg → checks then runs real npm
out_safe="$(npm install lodash 2>&1 || true)"
# install of evil pkg → blocked, real npm NOT run
out_evil="$(npm install evil 2>&1 || true)"
# non-install passes through untouched
out_run="$(npm run build 2>&1 || true)"
echo "SAFE=[$out_safe]"
echo "EVIL=[$out_evil]"
echo "RUN=[$out_run]"
`
	out, _ := exec.Command("bash", "-c", script).CombinedOutput()
	got := string(out)
	if !strings.Contains(got, "REAL_NPM install lodash") {
		t.Errorf("safe install should reach real npm: %s", got)
	}
	if strings.Contains(got, "REAL_NPM install evil") {
		t.Errorf("blocked install must NOT reach real npm: %s", got)
	}
	if !strings.Contains(got, "REAL_NPM run build") {
		t.Errorf("non-install must pass through: %s", got)
	}
}
