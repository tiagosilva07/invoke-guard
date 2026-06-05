package check

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/tiagosilva07/invoke-guard/internal/verdict"
)

// LockEntry is one resolved package in an npm lockfile (v2/v3 "packages" map).
type LockEntry struct {
	Name      string
	Version   string
	Resolved  string
	Integrity string
}

// LockChange records an existing entry whose resolved URL or integrity changed.
type LockChange struct {
	Name             string
	Version          string // head version (for display)
	OldResolved, New string
	OldIntegrity     string
	NewIntegrity     string
}

type npmLock struct {
	Packages map[string]struct {
		Version   string `json:"version"`
		Resolved  string `json:"resolved"`
		Integrity string `json:"integrity"`
	} `json:"packages"`
}

func parseLock(b []byte) (map[string]LockEntry, error) {
	if len(b) == 0 {
		return map[string]LockEntry{}, nil // empty/missing base → no packages
	}
	var l npmLock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	out := map[string]LockEntry{}
	for path, p := range l.Packages {
		if path == "" { // the root project entry
			continue
		}
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		out[name] = LockEntry{Name: name, Version: p.Version, Resolved: p.Resolved, Integrity: p.Integrity}
	}
	return out, nil
}

// DiffLockfiles returns packages newly added in head, and existing packages whose
// resolved URL or integrity hash changed (the lockfile-poisoning signal).
func DiffLockfiles(base, head []byte) (added []LockEntry, changed []LockChange, err error) {
	b, err := parseLock(base)
	if err != nil {
		return nil, nil, err
	}
	h, err := parseLock(head)
	if err != nil {
		return nil, nil, err
	}
	for name, he := range h {
		be, ok := b[name]
		if !ok {
			added = append(added, he)
			continue
		}
		if be.Resolved != he.Resolved || be.Integrity != he.Integrity {
			changed = append(changed, LockChange{
				Name: name, Version: he.Version, OldResolved: be.Resolved, New: he.Resolved,
				OldIntegrity: be.Integrity, NewIntegrity: he.Integrity,
			})
		}
	}
	return added, changed, nil
}

// LockfileIntegrity flags an existing dependency whose resolved tarball or integrity
// changed without (necessarily) a version bump — a lockfile-poisoning indicator.
func LockfileIntegrity(c LockChange) verdict.Signal {
	return verdict.Signal{
		Check:   verdict.RuleLockfileIntegrity,
		Level:   verdict.LevelBlock,
		Message: "existing dependency " + c.Name + " had its resolved URL/integrity changed in the lockfile — possible lockfile poisoning",
	}
}

// parseTOMLPackages extracts [[package]] blocks from Cargo.lock / poetry.lock. It
// is NOT a general TOML parser: it walks the flat [[package]] table-array both
// files use, reading `key = "value"` lines until the next table line.
func parseTOMLPackages(b []byte) []LockEntry {
	var out []LockEntry
	var cur *LockEntry
	in := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	flush := func() {
		if cur != nil && cur.Name != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[[package]]" {
			flush()
			cur = &LockEntry{}
			in = true
			continue
		}
		if strings.HasPrefix(line, "[") { // any other table ends the block
			flush()
			in = false
			continue
		}
		if !in || cur == nil {
			continue
		}
		k, v, ok := tomlKV(line)
		if !ok {
			continue
		}
		switch k {
		case "name":
			cur.Name = v
		case "version":
			cur.Version = v
		case "source":
			cur.Resolved = v
		case "checksum":
			cur.Integrity = v
		}
	}
	flush()
	return out
}

func tomlKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.Trim(strings.TrimSpace(line[i+1:]), `"`), true
}

var reqRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*(?:==\s*([A-Za-z0-9._-]+))?`)

// parseRequirements parses a requirements.txt into normalized name -> LockEntry.
func parseRequirements(b []byte) map[string]LockEntry {
	out := map[string]LockEntry{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqRe.FindStringSubmatch(line)
		if m == nil || m[1] == "" {
			continue
		}
		name := pyNormalize(m[1])
		out[name] = LockEntry{Name: name, Version: m[2]}
	}
	return out
}

var pySepRe = regexp.MustCompile(`[-_.]+`)

func pyNormalize(s string) string { return pySepRe.ReplaceAllString(strings.ToLower(s), "-") }

// ParseLock parses a lockfile into a name->LockEntry map for the given ecosystem.
func ParseLock(ecosystem string, b []byte) (map[string]LockEntry, error) {
	switch ecosystem {
	case "npm":
		return parseLock(b) // existing package-lock.json parser
	case "crates":
		return tomlToMap(parseTOMLPackages(b)), nil
	case "pypi":
		if bytes.Contains(b, []byte("[[package]]")) { // poetry.lock
			return tomlToMap(parseTOMLPackages(b)), nil
		}
		return parseRequirements(b), nil
	default:
		return nil, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
}

func tomlToMap(entries []LockEntry) map[string]LockEntry {
	m := make(map[string]LockEntry, len(entries))
	for _, e := range entries {
		m[e.Name] = e
	}
	return m
}

// DiffLockfilesEco diffs base vs head for the given ecosystem (added + changed).
func DiffLockfilesEco(ecosystem string, base, head []byte) (added []LockEntry, changed []LockChange, err error) {
	b, err := ParseLock(ecosystem, base)
	if err != nil {
		return nil, nil, err
	}
	h, err := ParseLock(ecosystem, head)
	if err != nil {
		return nil, nil, err
	}
	for name, he := range h {
		be, ok := b[name]
		if !ok {
			added = append(added, he)
			continue
		}
		if be.Resolved != he.Resolved || be.Integrity != he.Integrity {
			changed = append(changed, LockChange{Name: name, Version: he.Version, OldResolved: be.Resolved, New: he.Resolved, OldIntegrity: be.Integrity, NewIntegrity: he.Integrity})
		}
	}
	return added, changed, nil
}
