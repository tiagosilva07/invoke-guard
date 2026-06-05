package check

import "testing"

func FuzzDamerau(f *testing.F) {
	f.Add("request", "reqeust")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, a, b string) {
		d := Damerau(a, b)
		if d < 0 {
			t.Fatalf("negative distance %d", d)
		}
		if a == b && d != 0 {
			t.Fatalf("equal strings have distance %d", d)
		}
	})
}
