package check

import "github.com/tiagosilva07/zyrax-guard/internal/verdict"

// MaintainerChange flags when the publishing maintainer set gained a new account
// versus a known-good baseline — an account-takeover / handoff signal.
func MaintainerChange(baseline, current []string) verdict.Signal {
	known := map[string]bool{}
	for _, m := range baseline {
		known[m] = true
	}
	for _, m := range current {
		if !known[m] {
			return verdict.Signal{
				Check:   verdict.RuleMaintainerChange,
				Level:   verdict.LevelWarn,
				Message: "a new maintainer (" + m + ") now publishes this package — verify it is not an account takeover",
			}
		}
	}
	return verdict.Signal{Check: verdict.RuleMaintainerChange, Level: verdict.LevelInfo}
}
