#!/usr/bin/env bash
# Runs the project's toolchains in pinned containers, so that no local Go or
# Node installation is needed (#4).
#
#   tools/dev.sh go <args>    go command in the Go image, e.g. tools/dev.sh go test ./...
#   tools/dev.sh npm <args>   npm in e2e/, in the Playwright image
#   tools/dev.sh e2e [args]   builds the e2e binary, then runs the Playwright suite
#
# Module and build caches live under ~/.cache/passkey-auth.
set -euo pipefail

readonly GO_IMAGE=golang:1.27.1
readonly PW_IMAGE=mcr.microsoft.com/playwright:v1.64.0-noble

root=$(git rev-parse --show-toplevel)
cache=${XDG_CACHE_HOME:-$HOME/.cache}/passkey-auth
mkdir -p "$cache/gomod" "$cache/gobuild" "$cache/npm"

# The worktree's .git file points outside the mount: no VCS stamping.
run() {
  local image=$1 workdir=$2; shift 2
  docker run --rm --init \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e CI="${CI:-}" \
    -e GOFLAGS=-buildvcs=false -e GOMODCACHE=/cache/gomod -e GOCACHE=/cache/gobuild \
    -e npm_config_cache=/cache/npm \
    -v "$root":/src -v "$cache":/cache \
    -w "$workdir" --network host \
    "$image" "$@"
}

cmd=${1:-}
[[ -n $cmd ]] && shift
case $cmd in
  go)
    run "$GO_IMAGE" /src go "$@"
    ;;
  npm)
    run "$PW_IMAGE" /src/e2e npm "$@"
    ;;
  e2e)
    run "$GO_IMAGE" /src go build -tags e2e -o bin/passkey-auth-e2e ./cmd/passkey-auth
    run "$PW_IMAGE" /src/e2e sh -c 'npm ci --no-audit --no-fund && npx playwright test "$@"' e2e "$@"
    ;;
  *)
    echo "usage: tools/dev.sh go <args> | npm <args> | e2e [playwright args]" >&2
    exit 2
    ;;
esac
exit

return 0

# --- Change History -------------------------------------------------------
# | PR     | Summary                                                       |
# |--------|---------------------------------------------------------------|
# | #TBD   | containers for Go, npm and the e2e suite (issue #4)           |
