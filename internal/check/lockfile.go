package check

import (
	"encoding/json"
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
