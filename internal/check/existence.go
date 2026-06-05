package check

import "github.com/tiagosilva07/invoke-guard/internal/verdict"

// Existence turns a registry existence result into a signal. A non-existent
// package is a strong signal of a hallucinated or trap name → BLOCK.
func Existence(exists bool) verdict.Signal {
	if !exists {
		return verdict.Signal{
			Check:   verdict.RuleNonexistent,
			Level:   verdict.LevelBlock,
			Message: "package does not exist on the registry — likely a hallucinated or trap name",
		}
	}
	return verdict.Signal{Check: verdict.RuleNonexistent, Level: verdict.LevelInfo}
}
