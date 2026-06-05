package check

import (
	"testing"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

func TestExistence(t *testing.T) {
	if s := Existence(false); s.Level != verdict.LevelBlock {
		t.Errorf("missing package should BLOCK, got %v", s.Level)
	}
	if s := Existence(true); s.Level != verdict.LevelInfo {
		t.Errorf("existing package should be info, got %v", s.Level)
	}
}

func TestPopularity(t *testing.T) {
	now := time.Now()
	newLow := seam.Metadata{Exists: true, Published: now.AddDate(0, 0, -5), WeeklyLoads: 10}
	if s := Popularity(newLow); s.Level != verdict.LevelWarn {
		t.Errorf("new+low should WARN, got %v", s.Level)
	}
	old := seam.Metadata{Exists: true, Published: now.AddDate(-5, 0, 0), WeeklyLoads: 9_000_000}
	if s := Popularity(old); s.Level != verdict.LevelInfo {
		t.Errorf("old+popular should be info, got %v", s.Level)
	}
}
