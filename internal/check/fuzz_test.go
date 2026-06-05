package check

import "testing"

func FuzzDamerau(f *testing.F) {
	f.Add("request", "reqeust")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, a, b string) {
		// Damerau builds an O(len(a)*len(b)) matrix; real package names are length-
		// bounded by ValidateName (<=214). Bound fuzz inputs so this exercises the
		// distance LOGIC rather than memory/time limits (huge inputs otherwise OOM
		// the fuzzer non-deterministically).
		if len(a) > 256 || len(b) > 256 {
			return
		}
		d := Damerau(a, b)
		if d < 0 {
			t.Fatalf("negative distance %d", d)
		}
		if a == b && d != 0 {
			t.Fatalf("equal strings have distance %d", d)
		}
	})
}
