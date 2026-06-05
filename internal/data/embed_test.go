package data

import "testing"

func TestPopularNPMNonEmpty(t *testing.T) {
	if len(PopularNPM()) < 10 {
		t.Fatalf("expected a seed popular list, got %d", len(PopularNPM()))
	}
}
