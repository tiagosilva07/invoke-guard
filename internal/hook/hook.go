// Package hook renders shell snippets that wrap the package manager so that adding
// a dependency is gated by invoke-guard. The wrapper checks each new package name
// and, only if none is BLOCKed, runs the REAL package manager with the original
// args (so npm's own flags and non-install subcommands are untouched).
package hook

import "fmt"

// Snippet returns the shell snippet for shell ("bash", "zsh", or "powershell").
// The user adds it to their rc, e.g. eval "$(invoke-guard init zsh)".
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
const posixSnippet = `# invoke-guard npm guard — added by: eval "$(invoke-guard init bash)"
npm() {
  case "$1" in
    install|i|add)
      for __ig_arg in "${@:2}"; do
        case "$__ig_arg" in
          -*) : ;;  # skip flags (e.g. --save-dev, -g)
          *)
            if ! invoke-guard check "$__ig_arg"; then
              echo "invoke-guard: blocked \"$__ig_arg\" — override with: invoke-guard allow $__ig_arg" >&2
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
var powershellSnippet = "# invoke-guard npm guard — added by: Invoke-Expression (invoke-guard init powershell)\n" +
	"function npm {\n" +
	"  if ($args.Count -ge 1 -and @('install','i','add') -contains $args[0]) {\n" +
	"    foreach ($__ig_arg in $args[1..($args.Count-1)]) {\n" +
	"      if ($__ig_arg -notlike '-*') {\n" +
	"        & invoke-guard check $__ig_arg\n" +
	"        if ($LASTEXITCODE -ne 0) {\n" +
	"          Write-Error \"invoke-guard: blocked `\"$__ig_arg`\" — override with: invoke-guard allow $__ig_arg\"\n" +
	"          return\n" +
	"        }\n" +
	"      }\n" +
	"    }\n" +
	"  }\n" +
	"  $__ig_real = Get-Command -CommandType Application npm | Select-Object -First 1\n" +
	"  & $__ig_real.Source @args\n" +
	"}\n"
