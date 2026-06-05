// Command invoke-guard vets dependencies before install. Subcommands: check,
// install, allow, scan. Exit 0 for SAFE/WARN; non-zero for BLOCK (and for WARN
// under --strict).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tiagosilva07/invoke-guard/internal/check"
	"github.com/tiagosilva07/invoke-guard/internal/data"
	"github.com/tiagosilva07/invoke-guard/internal/report"
	"github.com/tiagosilva07/invoke-guard/internal/seam"
	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

var version = "dev" // set via -ldflags at release

func usage() string {
	return `invoke-guard — check a dependency before you install it

usage:
  invoke-guard check <name>[@version] [--json|--sarif] [--strict]
  invoke-guard install <names...> [--ignore-scripts] [--strict]
  invoke-guard allow <name>
  invoke-guard scan [--strict] [--json|--sarif]
  invoke-guard --version
`
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Print(usage())
		return 2
	}
	switch args[0] {
	case "--version", "version":
		fmt.Println(version)
		return 0
	case "--help", "-h", "help":
		fmt.Print(usage())
		return 0
	case "check":
		return cmdCheck(args[1:])
	case "install":
		return cmdInstall(args[1:])
	case "allow":
		return cmdAllow(args[1:])
	case "scan":
		return cmdScan(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", args[0], usage())
		return 2
	}
}

func splitNameVersion(s string) (string, string) {
	if i := strings.LastIndex(s, "@"); i > 0 { // i>0 keeps @scope intact
		return s[:i], s[i+1:]
	}
	return s, ""
}

func reporterFor(asJSON, asSARIF bool) seam.Reporter {
	switch {
	case asSARIF:
		return &report.SARIF{W: os.Stdout}
	case asJSON:
		return &report.JSON{W: os.Stdout}
	default:
		return &report.Text{W: os.Stdout, Color: term()}
	}
}

func term() bool { fi, _ := os.Stdout.Stat(); return fi != nil && (fi.Mode()&os.ModeCharDevice) != 0 }

func exitForVerdict(v string, strict bool) int {
	switch v {
	case "BLOCK":
		return 1
	case "WARN":
		if strict {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func cmdCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	asSARIF := fs.Bool("sarif", false, "SARIF output")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	name, ver := splitNameVersion(fs.Arg(0))
	orch, err := check.NewNPM(".", loadPopular())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	res := orch.Check(context.Background(), name, ver)
	reporterFor(*asJSON, *asSARIF).Report([]verdict.Result{res})
	return exitForVerdict(res.VerdictStr, *strict)
}

func cmdInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	ignoreScripts := fs.Bool("ignore-scripts", false, "pass --ignore-scripts to npm")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	names := fs.Args()
	if len(names) == 0 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	orch, err := check.NewNPM(".", loadPopular())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var results []verdict.Result
	worst := 0
	for _, raw := range names {
		n, v := splitNameVersion(raw)
		r := orch.Check(context.Background(), n, v)
		results = append(results, r)
		if c := exitForVerdict(r.VerdictStr, *strict); c > worst {
			worst = c
		}
	}
	reporterFor(false, false).Report(results)
	if worst != 0 {
		fmt.Fprintln(os.Stderr, "blocked — not installing. Override with: invoke-guard allow <name>")
		return worst
	}
	if err := orch.Eco.Install(context.Background(), bareNames(names), seam.InstallOpts{IgnoreScripts: *ignoreScripts}); err != nil {
		fmt.Fprintln(os.Stderr, "install failed:", err)
		return 1
	}
	return 0
}

func bareNames(raw []string) []string {
	out := make([]string, len(raw))
	for i, r := range raw {
		out[i], _ = splitNameVersion(r)
	}
	return out
}

func cmdAllow(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	orch, err := check.NewNPM(".", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if err := orch.Policy.Allow(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("allowed %q (recorded in .invoke/policy.json)\n", args[0])
	return 0
}

// cmdScan vets the dependencies a PR ADDS or CHANGES, by diffing the lockfile
// against a base. Only newly added/changed deps are checked, so it's fast and
// doesn't re-flag the whole tree. Reads base + head lockfiles from --base/--head
// (paths); defaults head to ./package-lock.json.
func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	basePath := fs.String("base", "", "base lockfile (e.g. the target branch's package-lock.json)")
	headPath := fs.String("head", "package-lock.json", "head lockfile")
	asJSON := fs.Bool("json", false, "JSON output")
	asSARIF := fs.Bool("sarif", false, "SARIF output")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	head, err := os.ReadFile(*headPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read head lockfile:", err)
		return 2
	}
	var base []byte
	if *basePath != "" {
		if base, err = os.ReadFile(*basePath); err != nil {
			fmt.Fprintln(os.Stderr, "read base lockfile:", err)
			return 2
		}
	} else {
		base = []byte(`{"packages":{}}`) // no base → treat all as added
	}
	added, changed, err := check.DiffLockfiles(base, head)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse lockfiles:", err)
		return 2
	}
	orch, err := check.NewNPM(".", loadPopular())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var results []verdict.Result
	for _, a := range added {
		results = append(results, orch.Check(context.Background(), a.Name, a.Version))
	}
	for _, c := range changed {
		r := verdict.Decide("npm", c.Name, c.Version, []verdict.Signal{check.LockfileIntegrity(c)})
		results = append(results, r)
	}
	reporterFor(*asJSON, *asSARIF).Report(results)
	var verdicts []string
	for _, r := range results {
		verdicts = append(verdicts, r.VerdictStr)
	}
	return scanExit(verdicts, *strict)
}

func scanExit(verdicts []string, strict bool) int {
	worst := 0
	for _, v := range verdicts {
		if c := exitForVerdict(v, strict); c > worst {
			worst = c
		}
	}
	return worst
}

func loadPopular() []string { return data.PopularNPM() }
