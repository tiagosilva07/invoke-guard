package check

import (
	"context"

	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// Orchestrator runs all package-level checks for one package and applies policy.
type Orchestrator struct {
	Eco    seam.Ecosystem
	Intel  seam.ThreatIntel
	Policy seam.Policy
}

// Check vets one package end-to-end and returns the verdict Result. Policy
// allow/deny short-circuits (with an explanatory signal) before the checks run.
func (o *Orchestrator) Check(ctx context.Context, name, version string) verdict.Result {
	return o.CheckWith(ctx, name, version, false)
}

// CheckWith vets a package; when deep, it also downloads the artifact and runs the
// install-script analyzer (best-effort: a fetch error is an Info signal, not a BLOCK).
func (o *Orchestrator) CheckWith(ctx context.Context, name, version string, deep bool) verdict.Result {
	switch o.Policy.Decide(name) {
	case seam.ForceAllow:
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: "policy-allow", Level: verdict.LevelInfo, Message: "explicitly allowed by local policy"},
		})
	case seam.ForceDeny:
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: "policy-deny", Level: verdict.LevelBlock, Message: "explicitly denied by local policy"},
		})
	}

	var signals []verdict.Signal
	exists, err := o.Eco.Exists(ctx, name, version)
	if err != nil {
		return verdict.Decide(o.Eco.Name(), name, version, []verdict.Signal{
			{Check: verdict.RuleCheckError, Level: verdict.LevelWarn, Message: "could not reach the registry to verify this package: " + err.Error()},
		})
	}
	signals = append(signals, Existence(exists))
	if !exists {
		return verdict.Decide(o.Eco.Name(), name, version, signals)
	}
	md, _ := o.Eco.Metadata(ctx, name)
	if version == "" {
		version = md.Latest // check the version a bare install would actually pull
	}
	signals = append(signals, Typosquat(name, md.WeeklyLoads, o.Eco.PopularList()))
	signals = append(signals, Popularity(md))
	if advs, err := o.Intel.Lookup(ctx, o.Eco.Name(), name, version); err == nil {
		signals = append(signals, KnownBad(advs))
	}
	if deep {
		if files, err := o.Eco.InstallCode(ctx, name, version); err != nil {
			signals = append(signals, verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelInfo, Message: "could not fetch artifact for deep analysis: " + err.Error()})
		} else {
			signals = append(signals, AnalyzeInstallScripts(o.Eco.Name(), files))
		}
	}
	return verdict.Decide(o.Eco.Name(), name, version, signals)
}
