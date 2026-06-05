package data

import "testing"

func TestPopularNPMNonEmpty(t *testing.T) {
	if len(PopularNPM()) < 10 {
		t.Fatalf("expected a seed popular list, got %d", len(PopularNPM()))
	}
}

func TestPopularPyPIAndCratesNonEmpty(t *testing.T) {
	if len(PopularPyPI()) < 10 {
		t.Errorf("pypi list too small: %d", len(PopularPyPI()))
	}
	if len(PopularCrates()) < 10 {
		t.Errorf("crates list too small: %d", len(PopularCrates()))
	}
}
