// Command zyrax-guard vets dependencies before install. Subcommands: check,
// install, allow, scan. Exit 0 for SAFE/WARN; non-zero for BLOCK (and for WARN
// under --strict).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tiagosilva07/zyrax-guard/internal/check"
	"github.com/tiagosilva07/zyrax-guard/internal/data"
	"github.com/tiagosilva07/zyrax-guard/internal/hook"
	"github.com/tiagosilva07/zyrax-guard/internal/mcp"
	"github.com/tiagosilva07/zyrax-guard/internal/report"
	"github.com/tiagosilva07/zyrax-guard/internal/seam"
	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

var version = "dev" // set via -ldflags at release

func usage() string {
	return `zyrax-guard — check a dependency before you install it

usage:
  zyrax-guard check <name>[@version] [--ecosystem npm|pypi|crates] [--json|--sarif] [--strict] [--deep]
  zyrax-guard install <names...> [--ecosystem npm|pypi|crates] [--ignore-scripts] [--strict] [--deep]
  zyrax-guard allow <name>
  zyrax-guard scan [--ecosystem npm|pypi|crates] [--base F] [--head F] [--strict] [--json|--sarif] [--deep]
  zyrax-guard mcp                                  (MCP server for AI agents; stdio)
  zyrax-guard init <bash|zsh|powershell> [npm|pip|cargo]   (shell hook: gate installs)
  zyrax-guard --version
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
	case "mcp":
		return cmdMCP(args[1:])
	case "init":
		return cmdInit(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", args[0], usage())
		return 2
	}
}

// reorderFlagsFirst moves leading-dash tokens ahead of operands so flags may
// appear after the package name(s). valueFlags names the flags that take a separate
// value token (e.g. "ecosystem"): their value stays attached to the flag rather than
// being mistaken for an operand. npm/pypi/crates names never start with '-'.
func reorderFlagsFirst(args []string, valueFlags ...string) []string {
	vf := map[string]bool{}
	for _, f := range valueFlags {
		vf["-"+f] = true
		vf["--"+f] = true
	}
	var flags, ops []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if vf[a] && i+1 < len(args) { // space-form value flag: keep its value
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		ops = append(ops, a)
	}
	return append(flags, ops...)
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
	eco := fs.String("ecosystem", "npm", "npm|pypi|crates")
	deep := fs.Bool("deep", false, "download + analyze install/build scripts")
	if err := fs.Parse(reorderFlagsFirst(args, "ecosystem")); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	name, ver := splitNameVersion(fs.Arg(0))
	orch, err := check.New(*eco, ".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	res := orch.CheckWith(context.Background(), name, ver, *deep)
	reporterFor(*asJSON, *asSARIF).Report([]verdict.Result{res})
	return exitForVerdict(res.VerdictStr, *strict)
}

func cmdInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	ignoreScripts := fs.Bool("ignore-scripts", false, "pass --ignore-scripts to npm")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	eco := fs.String("ecosystem", "npm", "npm|pypi|crates")
	deep := fs.Bool("deep", false, "download + analyze install/build scripts")
	if err := fs.Parse(reorderFlagsFirst(args, "ecosystem")); err != nil {
		return 2
	}
	names := fs.Args()
	if len(names) == 0 {
		fmt.Fprint(os.Stderr, usage())
		return 2
	}
	orch, err := check.New(*eco, ".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	var results []verdict.Result
	worst := 0
	for _, raw := range names {
		n, v := splitNameVersion(raw)
		r := orch.CheckWith(context.Background(), n, v, *deep)
		results = append(results, r)
		if c := exitForVerdict(r.VerdictStr, *strict); c > worst {
			worst = c
		}
	}
	reporterFor(false, false).Report(results)
	if worst != 0 {
		fmt.Fprintln(os.Stderr, "blocked — not installing. Override with: zyrax-guard allow <name>")
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
	if err := orch.Eco.ValidateName(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, "invalid package name:", err)
		return 2
	}
	if err := orch.Policy.Allow(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("allowed %q (recorded in .zyrax/policy.json)\n", args[0])
	return 0
}

// cmdScan vets the dependencies a PR ADDS or CHANGES, by diffing the lockfile
// against a base. Only newly added/changed deps are checked, so it's fast and
// doesn't re-flag the whole tree. Reads base + head lockfiles from --base/--head
// (paths); defaults head to the ecosystem's canonical lockfile name.
func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	basePath := fs.String("base", "", "base lockfile (e.g. the target branch's lockfile)")
	headPath := fs.String("head", "package-lock.json", "head lockfile")
	asJSON := fs.Bool("json", false, "JSON output")
	asSARIF := fs.Bool("sarif", false, "SARIF output")
	strict := fs.Bool("strict", false, "treat WARN as failure")
	eco := fs.String("ecosystem", "npm", "npm|pypi|crates")
	deep := fs.Bool("deep", false, "download + analyze install/build scripts")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Validate ecosystem early (before any file I/O).
	validEco := map[string]bool{"npm": true, "pypi": true, "crates": true}
	if !validEco[*eco] {
		fmt.Fprintf(os.Stderr, "unsupported ecosystem %q (use npm, pypi, or crates)\n", *eco)
		return 2
	}
	// Pick per-ecosystem default head path when the flag still holds the npm default.
	defaultHead := map[string]string{"npm": "package-lock.json", "crates": "Cargo.lock", "pypi": "poetry.lock"}
	if *headPath == "package-lock.json" {
		if h, ok := defaultHead[*eco]; ok {
			*headPath = h
		}
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
	}
	// base == nil → ParseLock on empty bytes → empty map → all head deps are "added"
	added, changed, err := check.DiffLockfilesEco(*eco, base, head)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse lockfiles:", err)
		return 2
	}
	orch, err := check.New(*eco, ".")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// With --deep, each added dep downloads + inspects its artifact (sequential).
	// Bound the whole pass with an overall deadline so a large diff can't run
	// unbounded in CI; once spent, remaining deps degrade to a metadata-only check
	// (best-effort — a deadline never turns a SAFE/WARN into a false BLOCK).
	ctx, cancel := scanDeepContext(context.Background(), *deep)
	defer cancel()
	var results []verdict.Result
	for _, a := range added {
		results = append(results, orch.CheckWith(ctx, a.Name, a.Version, *deep))
	}
	for _, c := range changed {
		r := verdict.Decide(*eco, c.Name, c.Version, []verdict.Signal{check.LockfileIntegrity(c)})
		results = append(results, r)
	}
	if *deep && ctx.Err() != nil {
		fmt.Fprintf(os.Stderr, "note: --deep time budget (%s) exceeded; remaining packages were checked without deep analysis\n", scanDeepBudget)
	}
	reporterFor(*asJSON, *asSARIF).Report(results)
	var verdicts []string
	for _, r := range results {
		verdicts = append(verdicts, r.VerdictStr)
	}
	return scanExit(verdicts, *strict)
}

// scanDeepBudget caps the total wall-clock of a `scan --deep` pass. It's
// generous for a typical PR diff (a handful of added deps) but stops a huge or
// slow diff from hanging CI; remaining deps degrade to metadata-only checks.
const scanDeepBudget = 3 * time.Minute

// scanDeepContext returns the context scan uses for each package check. With
// deep analysis it carries an overall deadline (scanDeepBudget); without it the
// parent is returned unbounded. The caller must always invoke the returned cancel.
func scanDeepContext(parent context.Context, deep bool) (context.Context, context.CancelFunc) {
	if !deep {
		return parent, func() {}
	}
	return context.WithTimeout(parent, scanDeepBudget)
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

func cmdMCP(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: zyrax-guard mcp   (no flags; serves MCP over stdio)")
		return 2
	}
	srv := &mcp.Server{Version: version, Resolve: func(eco string) (mcp.Checker, error) {
		return check.New(eco, ".")
	}}
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	return 0
}

func cmdInit(args []string) int {
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: zyrax-guard init <bash|zsh|powershell> [npm|pip|cargo]")
		return 2
	}
	mgr := "npm"
	if len(args) == 2 {
		mgr = args[1]
	}
	snippet, err := hook.SnippetFor(args[0], mgr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println(snippet)
	return 0
}

func loadPopular() []string { return data.PopularNPM() }
