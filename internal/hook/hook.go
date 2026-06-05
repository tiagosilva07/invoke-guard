// Package hook renders shell snippets that wrap the package manager so that adding
// a dependency is gated by zyrax-guard. The wrapper checks each new package name
// and, only if none is BLOCKed, runs the REAL package manager with the original
// args (so npm's own flags and non-install subcommands are untouched).
package hook

import "fmt"

// SnippetFor renders the guard wrapper for a package manager: npm (default),
// pip, or cargo. The wrapper gates the manager's add-dependency verb via
// `zyrax-guard check --ecosystem <eco>` and otherwise calls the real manager.
func SnippetFor(shell, manager string) (string, error) {
	var verb, eco string
	switch manager {
	case "npm", "":
		return Snippet(shell) // existing npm wrapper
	case "pip":
		verb, eco = "install", "pypi"
	case "cargo":
		verb, eco = "add", "crates"
	default:
		return "", fmt.Errorf("unsupported manager %q (use npm, pip, or cargo)", manager)
	}
	switch shell {
	case "bash", "zsh":
		return posixManagerSnippet(manager, verb, eco), nil
	case "powershell":
		return powershellManagerSnippet(manager, verb, eco), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (use bash, zsh, or powershell)", shell)
	}
}

func posixManagerSnippet(mgr, verb, eco string) string {
	return "# zyrax-guard " + mgr + " guard — added by: eval \"$(zyrax-guard init bash " + mgr + ")\"\n" +
		mgr + "() {\n" +
		"  if [ \"$1\" = \"" + verb + "\" ]; then\n" +
		"    for __ig_arg in \"${@:2}\"; do\n" +
		"      case \"$__ig_arg\" in\n" +
		"        -*) : ;;\n" +
		"        *)\n" +
		"          if ! zyrax-guard check --ecosystem " + eco + " \"$__ig_arg\"; then\n" +
		"            echo \"zyrax-guard: blocked \\\"$__ig_arg\\\" — override: zyrax-guard allow $__ig_arg\" >&2\n" +
		"            return 1\n" +
		"          fi\n" +
		"          ;;\n" +
		"      esac\n" +
		"    done\n" +
		"  fi\n" +
		"  command " + mgr + " \"$@\"\n" +
		"}\n"
}

func powershellManagerSnippet(mgr, verb, eco string) string {
	return "# zyrax-guard " + mgr + " guard\n" +
		"function " + mgr + " {\n" +
		"  if ($args.Count -ge 2 -and $args[0] -eq '" + verb + "') {\n" +
		"    foreach ($__ig_arg in $args[1..($args.Count-1)]) {\n" +
		"      if ($__ig_arg -notlike '-*') {\n" +
		"        & zyrax-guard check --ecosystem " + eco + " $__ig_arg\n" +
		"        if ($LASTEXITCODE -ne 0) { Write-Error \"zyrax-guard: blocked $__ig_arg\"; return }\n" +
		"      }\n" +
		"    }\n" +
		"  }\n" +
		"  $__ig_real = Get-Command -CommandType Application " + mgr + " | Select-Object -First 1\n" +
		"  & $__ig_real.Source @args\n" +
		"}\n"
}

// Snippet returns the shell snippet for shell ("bash", "zsh", or "powershell").
// The user adds it to their rc, e.g. eval "$(zyrax-guard init zsh)".
func Snippet(shell string) (string, error) {
	switch shell {
	case "bash", "zsh":
		return posixSnippet, nil
	case "powershell":
		return powershellSnippet, nil
	default:
		return "", fmt.Errorf("unsupported shell %q (use bash, zsh, or powershell)", shell)
	}
}

// posixSnippet works in bash and zsh (both support "${@:2}" array slicing). It
// gates install/i/add by checking each non-flag arg, then calls the real npm via
// `command npm` (never recursing into this function).
const posixSnippet = `# zyrax-guard npm guard — added by: eval "$(zyrax-guard init bash)"
npm() {
  case "$1" in
    install|i|add)
      for __ig_arg in "${@:2}"; do
        case "$__ig_arg" in
          -*) : ;;  # skip flags (e.g. --save-dev, -g)
          *)
            if ! zyrax-guard check "$__ig_arg"; then
              echo "zyrax-guard: blocked \"$__ig_arg\" — override with: zyrax-guard allow $__ig_arg" >&2
              return 1
            fi
            ;;
        esac
      done
      command npm "$@"
      ;;
    *) command npm "$@" ;;
  esac
}
`

// powershellSnippet defines a function that shadows npm; it resolves the REAL npm
// via Get-Command -CommandType Application (the function itself is type Function).
// Note: backtick is PowerShell's escape char; the string is built with concatenation
// because Go raw-string literals cannot contain backtick characters.
var powershellSnippet = "# zyrax-guard npm guard — added by: Invoke-Expression (zyrax-guard init powershell)\n" +
	"function npm {\n" +
	"  if ($args.Count -ge 2 -and @('install','i','add') -contains $args[0]) {\n" +
	"    foreach ($__ig_arg in $args[1..($args.Count-1)]) {\n" +
	"      if ($__ig_arg -notlike '-*') {\n" +
	"        & zyrax-guard check $__ig_arg\n" +
	"        if ($LASTEXITCODE -ne 0) {\n" +
	"          Write-Error \"zyrax-guard: blocked `\"$__ig_arg`\" — override with: zyrax-guard allow $__ig_arg\"\n" +
	"          return\n" +
	"        }\n" +
	"      }\n" +
	"    }\n" +
	"  }\n" +
	"  $__ig_real = Get-Command -CommandType Application npm | Select-Object -First 1\n" +
	"  & $__ig_real.Source @args\n" +
	"}\n"
