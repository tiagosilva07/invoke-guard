package verdict

// Decide combines signals into a single Result. BLOCK if any signal is LevelBlock;
// else WARN if any is LevelWarn; else SAFE. Score is a simple weighted sum
// (block=100, warn=10, info=1) so callers can sort by risk. The first non-empty
// Suggest is surfaced as the Result's suggestion.
func Decide(ecosystem, name, version string, signals []Signal) Result {
	v := Safe
	score := 0
	suggestion := ""
	for _, s := range signals {
		switch s.Level {
		case LevelBlock:
			if v < Block {
				v = Block
			}
			score += 100
		case LevelWarn:
			if v < Warn {
				v = Warn
			}
			score += 10
		default:
			score++
		}
		if suggestion == "" && s.Suggest != "" {
			suggestion = s.Suggest
		}
	}
	return Result{
		Ecosystem:  ecosystem,
		Name:       name,
		Version:    version,
		Verdict:    v,
		VerdictStr: v.String(),
		Score:      score,
		Signals:    signals,
		Suggestion: suggestion,
	}
}
