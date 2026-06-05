package check

import (
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func TestParseTOMLPackages(t *testing.T) {
	cargo := `# Cargo.lock
[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc123"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "def456"

[metadata]
ignored = "yes"
`
	entries := parseTOMLPackages([]byte(cargo))
	if len(entries) != 2 || entries[0].Name != "serde" || entries[0].Version != "1.0.197" || entries[0].Integrity != "abc123" {
		t.Fatalf("cargo parse wrong: %+v", entries)
	}
}

func TestParseRequirements(t *testing.T) {
	req := `# comment
requests==2.31.0
Flask[async]==3.0.0
-e ./local
urllib3 >= 1.26
`
	m := parseRequirements([]byte(req))
	if m["requests"].Version != "2.31.0" {
		t.Fatalf("requests: %+v", m["requests"])
	}
	if _, ok := m["flask"]; !ok { // normalized lowercase, extras stripped
		t.Fatalf("flask missing: %+v", m)
	}
}

func TestParseLockDispatch(t *testing.T) {
	cargo := "[[package]]\nname = \"serde\"\nversion = \"1.0\"\n"
	m, err := ParseLock("crates", []byte(cargo))
	if err != nil || m["serde"].Version != "1.0" {
		t.Fatalf("dispatch crates: %+v err=%v", m, err)
	}
}

func TestParseLockAdded(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"},"node_modules/b":{"version":"2.0.0","resolved":"https://r/b","integrity":"sha-B"}}}`
	added, changed, err := DiffLockfiles([]byte(base), []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0].Name != "b" {
		t.Fatalf("added = %+v", added)
	}
	if len(changed) != 0 {
		t.Fatalf("changed = %+v", changed)
	}
}

func TestLockIntegrityChanged(t *testing.T) {
	base := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://r/a","integrity":"sha-A"}}}`
	head := `{"packages":{"node_modules/a":{"version":"1.0.0","resolved":"https://EVIL/a","integrity":"sha-X"}}}`
	_, changed, _ := DiffLockfiles([]byte(base), []byte(head))
	if len(changed) != 1 {
		t.Fatalf("expected 1 integrity change, got %+v", changed)
	}
	if s := LockfileIntegrity(changed[0]); s.Level != verdict.LevelBlock {
		t.Errorf("integrity change should BLOCK, got %v", s.Level)
	}
}

func TestMaintainerChange(t *testing.T) {
	if s := MaintainerChange([]string{"alice"}, []string{"bob"}); s.Level != verdict.LevelWarn {
		t.Errorf("new maintainer should WARN, got %v", s.Level)
	}
	if s := MaintainerChange([]string{"alice"}, []string{"alice"}); s.Level != verdict.LevelInfo {
		t.Errorf("same maintainer should be info, got %v", s.Level)
	}
}

func TestDiffLockfilesEco_EmptyBaseAllAdded(t *testing.T) {
	// A missing/empty base lockfile must parse to no packages (all head deps "added"),
	// for every ecosystem — npm's JSON parser must tolerate empty input too.
	heads := map[string][]byte{
		"npm":    []byte(`{"packages":{"node_modules/a":{"version":"1.0.0"}}}`),
		"crates": []byte("[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n"),
		"pypi":   []byte("a==1.0.0\n"),
	}
	for eco, head := range heads {
		added, _, err := DiffLockfilesEco(eco, nil, head)
		if err != nil {
			t.Fatalf("%s: empty base errored: %v", eco, err)
		}
		if len(added) != 1 || added[0].Name != "a" {
			t.Fatalf("%s: want 1 added 'a', got %+v", eco, added)
		}
	}
}
