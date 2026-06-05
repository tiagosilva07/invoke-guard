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
		for _, want := range []string{"install", "add", "zyrax-guard check"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s snippet missing %q", sh, want)
			}
		}
	}
	if _, err := Snippet("fish"); err == nil {
		t.Error("unknown shell should error")
	}
}

func TestPowershellBareInstallNotChecked(t *testing.T) {
	// A bare `npm install` (no package args) must NOT vet the verb itself.
	// PowerShell's $args[1..0] descending-range trap is avoided by gating on
	// Count -ge 2, so the foreach only runs when there is at least one package.
	s, _ := Snippet("powershell")
	if !strings.Contains(s, "$args.Count -ge 2") {
		t.Errorf("powershell snippet must gate the check loop on Count -ge 2 (bare install safety):\n%s", s)
	}
}

func TestManagerSnippets(t *testing.T) {
	cases := []struct{ mgr, verb, ecoFlag string }{
		{"pip", "install", "pypi"},
		{"cargo", "add", "crates"},
	}
	for _, c := range cases {
		s, err := SnippetFor("bash", c.mgr)
		if err != nil {
			t.Fatalf("%s: %v", c.mgr, err)
		}
		for _, want := range []string{c.mgr + "()", c.verb, "zyrax-guard check --ecosystem " + c.ecoFlag, "command " + c.mgr} {
			if !strings.Contains(s, want) {
				t.Errorf("%s snippet missing %q:\n%s", c.mgr, want, s)
			}
		}
	}
	if _, err := SnippetFor("bash", "yarn"); err == nil {
		t.Error("unknown manager should error")
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
	// Stub `zyrax-guard` (blocks "evil", allows others) and `command` is real.
	// Define a stub real npm by shadowing PATH lookup: we assert routing via echo.
	script := `
set -e
` + s + `
zyrax-guard() { case "$2" in evil) echo "BLOCK"; return 1;; *) return 0;; esac; }
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
