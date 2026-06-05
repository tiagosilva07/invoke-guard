package check

import (
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

// KnownBad turns advisories into a signal. Malware or high/critical severity →
// BLOCK; anything lower → WARN; none → info.
func KnownBad(advs []seam.Advisory) verdict.Signal {
	worst := verdict.LevelInfo
	msg := ""
	for _, a := range advs {
		switch {
		case a.Malware || a.Severity == "critical" || a.Severity == "high":
			return verdict.Signal{Check: verdict.RuleKnownMalware, Level: verdict.LevelBlock, Message: advMsg(a)}
		default:
			if worst < verdict.LevelWarn {
				worst, msg = verdict.LevelWarn, advMsg(a)
			}
		}
	}
	return verdict.Signal{Check: verdict.RuleKnownMalware, Level: worst, Message: msg}
}

func advMsg(a seam.Advisory) string {
	if a.Summary != "" {
		return a.ID + ": " + a.Summary
	}
	return a.ID
}
