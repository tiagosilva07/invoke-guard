package main

import "testing"

func TestScanUnknownEcosystemExits2(t *testing.T) {
	if got := run([]string{"scan", "--ecosystem", "bogus", "--head", "x"}); got != 2 {
		t.Errorf("scan bogus eco exit = %d, want 2", got)
	}
}

func TestScanWorstExit(t *testing.T) {
	// helper that reduces a set of verdict strings + strict to an exit code
	if scanExit([]string{"SAFE", "WARN"}, false) != 0 {
		t.Error("safe+warn non-strict should be 0")
	}
	if scanExit([]string{"SAFE", "WARN"}, true) == 0 {
		t.Error("warn strict should be non-zero")
	}
	if scanExit([]string{"BLOCK"}, false) == 0 {
		t.Error("block should be non-zero")
	}
}
