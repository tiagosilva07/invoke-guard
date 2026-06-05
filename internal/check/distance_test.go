package check

import "testing"

func TestDamerau(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"request", "request", 0},
		{"reqeust", "request", 1}, // transposition
		{"expres", "express", 1},  // deletion
		{"lodahs", "lodash", 1},   // transposition
		{"abc", "xyz", 3},
	}
	for _, c := range cases {
		if got := Damerau(c.a, c.b); got != c.want {
			t.Errorf("Damerau(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}
