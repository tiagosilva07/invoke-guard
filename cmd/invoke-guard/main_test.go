package main

import (
	"strings"
	"testing"
)

func TestExitCodeForVerdict(t *testing.T) {
	if exitForVerdict("BLOCK", false) == 0 {
		t.Error("BLOCK must be non-zero")
	}
	if exitForVerdict("WARN", false) != 0 {
		t.Error("WARN non-strict must be 0")
	}
	if exitForVerdict("WARN", true) == 0 {
		t.Error("WARN strict must be non-zero")
	}
	if exitForVerdict("SAFE", true) != 0 {
		t.Error("SAFE must be 0")
	}
}

func TestUsageMentionsCommands(t *testing.T) {
	if !strings.Contains(usage(), "check") || !strings.Contains(usage(), "scan") {
		t.Error("usage must list commands")
	}
}

func TestReorderFlagsFirst(t *testing.T) {
	got := reorderFlagsFirst([]string{"express", "--json", "lodash", "--strict"})
	want := []string{"--json", "--strict", "express", "lodash"}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestUsageMentionsNewCommands(t *testing.T) {
	u := usage()
	for _, want := range []string{"mcp", "init"} {
		if !strings.Contains(u, want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestInitUnknownShellExits2(t *testing.T) {
	if got := run([]string{"init", "fish"}); got != 2 {
		t.Errorf("init fish exit = %d, want 2", got)
	}
}

func TestInitBashPrintsSnippet(t *testing.T) {
	// run() returns the exit code; just assert success for a known shell.
	if got := run([]string{"init", "bash"}); got != 0 {
		t.Errorf("init bash exit = %d, want 0", got)
	}
}
