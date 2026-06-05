package check

import (
	"fmt"
	"time"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

const (
	newAgeDays    = 30
	lowWeeklyLoad = 50
)

// Popularity flags packages that are both very new and barely used. It never
// blocks on its own — it raises suspicion (WARN) to be combined with other signals.
func Popularity(md seam.Metadata) verdict.Signal {
	if !md.Exists || md.Published.IsZero() {
		return verdict.Signal{Check: verdict.RuleNewAndUnused, Level: verdict.LevelInfo}
	}
	ageDays := int(time.Since(md.Published).Hours() / 24)
	if ageDays < newAgeDays && md.WeeklyLoads < lowWeeklyLoad {
		return verdict.Signal{
			Check:   verdict.RuleNewAndUnused,
			Level:   verdict.LevelWarn,
			Message: fmt.Sprintf("published %d days ago with only %d weekly downloads", ageDays, md.WeeklyLoads),
		}
	}
	return verdict.Signal{Check: verdict.RuleNewAndUnused, Level: verdict.LevelInfo}
}
