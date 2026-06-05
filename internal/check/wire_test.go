package check

import "testing"

func TestNewEcosystems(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "crates"} {
		o, err := New(eco, t.TempDir())
		if err != nil {
			t.Fatalf("New(%q): %v", eco, err)
		}
		if o.Eco.Name() != eco {
			t.Errorf("New(%q).Eco.Name() = %q", eco, o.Eco.Name())
		}
	}
	if _, err := New("bogus", t.TempDir()); err == nil {
		t.Error("unknown ecosystem should error")
	}
}
