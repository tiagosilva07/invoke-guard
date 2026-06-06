package check

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

var (
	reNetwork = regexp.MustCompile(`(?i)\bcurl\b|\bwget\b|https?://|require\(['"]https?['"]\)|fetch\(|urllib|requests\.(get|post)|Net::HTTP|reqwest|socket`)
	reSpawn   = regexp.MustCompile(`child_process|\bexec(Sync)?\(|\bspawn\(|os\.system|subprocess|Command::new|std::process|popen|\bsh\b|\bbash\b`)
	reObfusc  = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}|Buffer\.from\([^)]*base64|atob\(|\beval\(|\bFunction\(|(\\x[0-9a-fA-F]{2}){20,}`)
	reSensit  = regexp.MustCompile(`(?i)\.ssh|/etc/|id_rsa|\.npmrc|AWS_SECRET|process\.env`)
)

// AnalyzeInstallScripts runs static red-flag heuristics over a package's install-time
// code (already extracted, path->content). Returns a RuleSuspiciousInstall signal.
func AnalyzeInstallScripts(ecosystem string, files map[string]string) verdict.Signal {
	body, present := installBody(ecosystem, files)
	info := func(msg string) verdict.Signal {
		return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelInfo, Message: msg}
	}
	if !present {
		return info("no install/build scripts found")
	}
	net := reNetwork.MatchString(body)
	spawn := reSpawn.MatchString(body)
	obf := reObfusc.MatchString(body)
	sens := reSensit.MatchString(body)

	var hits []string
	if net {
		hits = append(hits, "network access")
	}
	if spawn {
		hits = append(hits, "process spawning")
	}
	if obf {
		hits = append(hits, "obfuscation/eval")
	}
	if sens {
		hits = append(hits, "sensitive file/env access")
	}

	strong := (net && (spawn || obf)) || (obf && reEvalBlob.MatchString(body))
	switch {
	case strong:
		return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelBlock,
			Message: "install/build script does dangerous things (" + strings.Join(hits, ", ") + ") — likely malicious"}
	case len(hits) > 0:
		return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelWarn,
			Message: "install/build script flagged (" + strings.Join(hits, ", ") + ") — review before installing"}
	default:
		return verdict.Signal{Check: verdict.RuleSuspiciousInstall, Level: verdict.LevelWarn,
			Message: "install/build script present but no red flags — review before installing"}
	}
}

var reEvalBlob = regexp.MustCompile(`(?is)(eval|Function)\([^)]*(base64|atob|Buffer\.from)`)

// installBody returns the concatenated install-time code for the ecosystem and
// whether any install-time code is present at all. Per-ecosystem extraction is
// split into helpers to keep each unit small and focused.
func installBody(ecosystem string, files map[string]string) (string, bool) {
	var b strings.Builder
	add := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	var present bool
	switch ecosystem {
	case "npm":
		present = npmInstallBody(files, add)
	case "pypi":
		present = pypiInstallBody(files, add)
	case "crates":
		present = cratesInstallBody(files, add)
	}
	return b.String(), present
}

// npmInstallBody gathers package.json lifecycle scripts plus any bundled
// .js/.cjs/.sh files a hook may invoke.
func npmInstallBody(files map[string]string, add func(string)) bool {
	present := false
	for p, c := range files {
		base := path.Base(p)
		if base == "package.json" {
			present = npmLifecycleScripts(c, add) || present
		}
		if strings.HasSuffix(base, ".js") || strings.HasSuffix(base, ".cjs") || strings.HasSuffix(base, ".sh") {
			present = true
			add(c)
		}
	}
	return present
}

// npmLifecycleScripts extracts preinstall/install/postinstall from a package.json body.
func npmLifecycleScripts(pkgJSON string, add func(string)) bool {
	var pj struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal([]byte(pkgJSON), &pj) != nil {
		return false
	}
	present := false
	for k, v := range pj.Scripts {
		if k == "preinstall" || k == "install" || k == "postinstall" {
			present = true
			add(v)
		}
	}
	return present
}

// pypiInstallBody gathers sdist build/config files.
func pypiInstallBody(files map[string]string, add func(string)) bool {
	present := false
	for p, c := range files {
		switch path.Base(p) {
		case "setup.py", "setup.cfg", "pyproject.toml":
			present = true
			add(c)
		}
	}
	return present
}

// cratesInstallBody gathers build.rs and notes a custom build target in Cargo.toml.
func cratesInstallBody(files map[string]string, add func(string)) bool {
	present := false
	for p, c := range files {
		base := path.Base(p)
		if base == "build.rs" {
			present = true
			add(c)
		}
		if base == "Cargo.toml" && strings.Contains(c, "build =") {
			present = true
		}
	}
	return present
}
