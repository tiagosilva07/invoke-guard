#!/bin/sh
# Zyrax Guard installer. Downloads a signed release binary for your OS/arch,
# verifies its SHA-256 against the release checksums, and installs it.
#
#   curl -fsSL https://raw.githubusercontent.com/tiagosilva07/zyrax-guard/main/scripts/install.sh | sh
#
# Env / args:
#   VERSION    release tag to install (default: latest).  Also: first positional arg.
#   BINDIR     install dir (default: /usr/local/bin if writable, else ~/.local/bin)
#   REPO       owner/name (default: tiagosilva07/zyrax-guard)
#
# Used by the GitHub Action (action.yml) too, so it must stay POSIX sh and
# dependency-light (curl, uname, sha256 tool).
set -eu

REPO="${REPO:-tiagosilva07/zyrax-guard}"
VERSION="${VERSION:-${1:-latest}}"
BIN="zyrax-guard"

say()  { printf '%s\n' "$*"; }
die()  { printf 'install: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || die "curl is required"

# ── detect platform ───────────────────────────────────────────────────────────
os=$(uname -s)
case "$os" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  MINGW*|MSYS*|CYGWIN*) os=windows ;;
  *) die "unsupported OS: $os" ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported arch: $arch" ;;
esac
ext=""
[ "$os" = windows ] && ext=".exe"
asset="${BIN}-${os}-${arch}${ext}"

# ── resolve version ────────────────────────────────────────────────────────────
if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || die "could not resolve latest version (set VERSION=vX.Y.Z)"
fi
base="https://github.com/${REPO}/releases/download/${VERSION}"

# ── download + verify ───────────────────────────────────────────────────────────
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
say "Downloading ${asset} ${VERSION}…"
curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}" || die "download failed: ${base}/${asset}"
curl -fsSL -o "${tmp}/checksums.txt" "${base}/checksums.txt" || die "download checksums failed"

want=$(grep " ${asset}\$" "${tmp}/checksums.txt" | awk '{print $1}' | head -n1)
[ -n "$want" ] || die "no checksum for ${asset} in checksums.txt"
if have sha256sum; then
  got=$(sha256sum "${tmp}/${asset}" | awk '{print $1}')
elif have shasum; then
  got=$(shasum -a 256 "${tmp}/${asset}" | awk '{print $1}')
else
  die "need sha256sum or shasum to verify the download"
fi
[ "$want" = "$got" ] || die "checksum mismatch for ${asset} (expected ${want}, got ${got})"
say "Checksum verified."

# Optional: cosign verification when available (release ships .cosign.bundle).
if have cosign; then
  if curl -fsSL -o "${tmp}/${asset}.cosign.bundle" "${base}/${asset}.cosign.bundle" 2>/dev/null; then
    cosign verify-blob --bundle "${tmp}/${asset}.cosign.bundle" "${tmp}/${asset}" >/dev/null 2>&1 \
      && say "Signature verified (cosign)." || say "warning: cosign verification could not be completed (continuing)."
  fi
fi

# ── install ─────────────────────────────────────────────────────────────────────
if [ -z "${BINDIR:-}" ]; then
  if [ -w /usr/local/bin ] 2>/dev/null; then BINDIR=/usr/local/bin; else BINDIR="${HOME}/.local/bin"; fi
fi
mkdir -p "$BINDIR"
target="${BINDIR}/${BIN}${ext}"
mv "${tmp}/${asset}" "$target"
chmod +x "$target"
say "Installed ${BIN} ${VERSION} -> ${target}"

case ":${PATH}:" in
  *":${BINDIR}:"*) ;;
  *) say "note: ${BINDIR} is not on your PATH — add it, e.g.  export PATH=\"${BINDIR}:\$PATH\"" ;;
esac
