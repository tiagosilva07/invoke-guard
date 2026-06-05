// Package data embeds the bundled popular-package lists so the binary is fully
// self-contained (no runtime file dependency).
package data

import (
	_ "embed"
	"encoding/json"
)

//go:embed popular-npm.json
var popularNPMRaw []byte

// PopularNPM returns the bundled top-npm names.
func PopularNPM() []string {
	var out []string
	_ = json.Unmarshal(popularNPMRaw, &out)
	return out
}

//go:embed popular-pypi.json
var popularPyPIRaw []byte

//go:embed popular-crates.json
var popularCratesRaw []byte

// PopularPyPI returns the bundled top-PyPI names (normalized).
func PopularPyPI() []string {
	var out []string
	_ = json.Unmarshal(popularPyPIRaw, &out)
	return out
}

// PopularCrates returns the bundled top-crates names.
func PopularCrates() []string {
	var out []string
	_ = json.Unmarshal(popularCratesRaw, &out)
	return out
}
