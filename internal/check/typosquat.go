package check

import (
	"fmt"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// Thresholds (conservative defaults; see spec §13 open question 1).
const (
	blockDistance = 1  // <= this distance to a popular name
	warnDistance  = 2  // <= this distance (but > blockDistance) → WARN
	lowDownloads  = 50 // queried package itself this-or-fewer weekly downloads
)

// Typosquat flags a name that is a near-miss of a much-more-popular package while
// itself having near-zero usage. An exact match to a popular name is the popular
// package itself → no flag. Returns a verdict.Signal (LevelInfo if nothing fires).
func Typosquat(name string, ownLoads int, popular []string) verdict.Signal {
	best, bestDist := "", 1<<30
	for _, p := range popular {
		if p == name {
			return verdict.Signal{Check: verdict.RuleTyposquat, Level: verdict.LevelInfo}
		}
		if dd := Damerau(name, p); dd < bestDist {
			best, bestDist = p, dd
		}
	}
	switch {
	case bestDist <= blockDistance && ownLoads <= lowDownloads:
		return verdict.Signal{
			Check:   verdict.RuleTyposquat,
			Level:   verdict.LevelBlock,
			Message: fmt.Sprintf("looks like a typo of %q (far more popular); this name has only %d weekly downloads", best, ownLoads),
			Suggest: best,
		}
	case bestDist <= warnDistance:
		return verdict.Signal{
			Check:   verdict.RuleTyposquat,
			Level:   verdict.LevelWarn,
			Message: fmt.Sprintf("name is similar to %q — double-check you meant this package", best),
			Suggest: best,
		}
	}
	return verdict.Signal{Check: verdict.RuleTyposquat, Level: verdict.LevelInfo}
}
