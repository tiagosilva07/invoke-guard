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
