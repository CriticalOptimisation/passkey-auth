#!/usr/bin/env bash
# Edge cases of `tools/image.sh pins` (#17, docs/container.md). Plain bash, no
# Docker, no network. Each case checks the exit status, stdout and stderr.
#
#   tools/image-pins.test.sh              exit 1 if a case fails
set -uo pipefail

image=$(git rev-parse --show-toplevel)/tools/image.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

hex=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
failed=0

# check <title> <status> <stdout> <stderr> -- <pins arguments...>: runs pins
# and compares its exit status and both streams with the expected ones.
check() {
  local title=$1 status=$2 out=$3 err=$4 got; shift 5
  got=0
  "$image" pins "$@" >"$work/out" 2>"$work/err" || got=$?
  if [[ $got != "$status" || $(<"$work/out") != "$out" || $(<"$work/err") != "$err" ]]; then
    echo "FAIL $title"
    echo "  status $got, expected $status"
    echo "  stdout: $(<"$work/out")"
    echo "  stderr: $(<"$work/err")"
    failed=1
  else
    echo "ok   $title"
  fi
}
bad_digest() { echo "image.sh: pins: $1: not pinned by digest"; }
bad_tag() { echo "image.sh: pins: $1: image of the containers project without an -immutable tag"; }

r=quay.io/skopeo/stable:v1.22.3-immutable@sha256:$hex
check "-immutable and digest on quay.io/skopeo/stable pass" 0 "ok $r" "" -- "$r"

r=quay.io/skopeo/stable:v1.22.3@sha256:$hex
check "plain tag on quay.io/skopeo/stable fails" 1 "" "$(bad_tag "$r")" -- "$r"

r=quay.io/containers/podman:v5.4.0@sha256:$hex
check "plain tag on quay.io/containers/podman fails" 1 "" "$(bad_tag "$r")" -- "$r"

r=quay.io/containers/aio:2026-10-01@sha256:$hex
check "quay.io/containers/aio is outside the convention" 0 "ok $r" "" -- "$r"

r=quay.io/skopeo/stable:v1.22.3-immutable
check "-immutable without a digest fails" 1 "" "$(bad_digest "$r")" -- "$r"

r=quay.io/skopeo/stable:v1.22.3-immutable@sha256:${hex:1}
check "digest of 63 hex digits fails" 1 "" "$(bad_digest "$r")" -- "$r"

r=moby/buildkit@sha256:$hex
check "reference without a tag fails" 1 "" "$(bad_digest "$r")" -- "$r"

r=localhost:5000/x:v1@sha256:$hex
check "registry with a port passes" 0 "ok $r" "" -- "$r"

r=localhost:5000/x@sha256:$hex
check "registry with a port and no tag fails" 1 "" "$(bad_digest "$r")" -- "$r"

good=moby/buildkit:v0.33.0@sha256:$hex
plain=quay.io/buildah/stable:v1.40.0@sha256:$hex
nodigest=golang:1.25
check "a mix exits 1 and names only the bad ones" 1 "ok $good" \
  "$(bad_tag "$plain")"$'\n'"$(bad_digest "$nodigest")" -- "$plain" "$good" "$nodigest"

own() { sed -n "s/^readonly $1=//p" "$image"; }
check "no argument checks the script's own pins" 0 \
  "ok $(own BUILDKIT_IMAGE)"$'\n'"ok $(own SKOPEO_IMAGE)" "" --

usage=$("$image" 2>&1)
check "-x is a usage error" 2 "" "$usage" -- -x

exit "$failed"

return 0

# --- Change History -------------------------------------------------------
# | PR     | Summary                                                       |
# |--------|---------------------------------------------------------------|
# | #19    | edge cases of image.sh pins                                   |
