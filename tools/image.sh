#!/usr/bin/env bash
# Builds and checks the container image (#6, docs/container.md). Docker with
# buildx only: no local Go. The CI workflow image.yml runs the same commands.
#
#   tools/image.sh build <out.tar>        OCI archive of the working tree; prints its digest
#   tools/image.sh digest <archive>       image manifest digest of an archive
#   tools/image.sh compare <a.tar> <b.tar> exit 1 unless both digests are equal
#   tools/image.sh repro                  two builds on new builders, no cache, then compare
#   tools/image.sh size <archive>         compressed/uncompressed sizes; exit 1 above 30 MB
#   tools/image.sh smoke <archive>        runs the image hardened and checks it
#
# Exit status: 0 success, 1 a check or a build failed, 2 usage error.
set -euo pipefail

readonly BUILDKIT_IMAGE=moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3
readonly SKOPEO_IMAGE=quay.io/skopeo/stable:v1.22.3@sha256:3cee4b44cb54d59f5b8822f8ca6379d6aafa4308834e5d9d958f5a4dc553a428
readonly PLATFORM=linux/amd64
readonly IMAGE_USER=65532:65532
readonly MAX_BYTES=30000000
readonly MANIFEST_TYPE=application/vnd.oci.image.manifest.v1+json
# Files that enter the image (see .dockerignore).
readonly CONTEXT_PATHS=(Dockerfile .dockerignore go.mod go.sum cmd internal web)

root=$(git rev-parse --show-toplevel)

die() { echo "image.sh: $*" >&2; exit 1; }
usage() {
  echo "usage: tools/image.sh build <out.tar> | digest <archive> | compare <a.tar> <b.tar> | repro | size <archive> | smoke <archive>" >&2
  exit 2
}
need() { local n=$1; shift; [[ $# -eq $n ]] || usage; }

# blob <archive> <sha256:hex>: the content of one blob of an OCI archive.
blob() { tar -xOf "$1" "blobs/sha256/${2#sha256:}"; }

# manifest_digest <archive>: the digest of the single image manifest.
manifest_digest() {
  local archive=$1 index
  [[ -f $archive ]] || die "$archive: no such archive"
  index=$(tar -xOf "$archive" index.json 2>/dev/null) || die "$archive: not an OCI archive (no index.json)"
  jq -er --arg t "$MANIFEST_TYPE" \
    'if (.manifests | length) == 1 and .manifests[0].mediaType == $t
     then .manifests[0].digest else empty end' <<<"$index" \
    || die "$archive: expected exactly one image manifest (BuildKit attestations must be off)"
}

# builder <name>: creates the builder on the pinned BuildKit image if missing.
builder() {
  docker buildx inspect "$1" >/dev/null 2>&1 \
    || docker buildx create --name "$1" --driver docker-container \
         --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null
}

# build <out.tar> [builder]: the OCI archive of the working tree.
build() {
  local out=$1 name=${2:-passkey-auth-${BUILDKIT_IMAGE##*sha256:}}
  name=${name:0:40}
  [[ -f $root/Dockerfile ]] || die "no Dockerfile in $root"
  if [[ -n $(git -C "$root" status --porcelain -- "${CONTEXT_PATHS[@]}") ]]; then
    echo "image.sh: warning: uncommitted changes in the build context; the digest is not that of $(git -C "$root" rev-parse --short HEAD)" >&2
  fi
  builder "$name"
  SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct) \
  docker buildx build --builder "$name" --platform "$PLATFORM" \
    --no-cache --pull --provenance=false --sbom=false \
    --build-arg "REVISION=$(git -C "$root" rev-parse HEAD)" \
    --tag passkey-auth:build \
    --output "type=oci,dest=$out,rewrite-timestamp=true" \
    "$root" >&2 || die "build failed"
  manifest_digest "$out"
}

compare() {
  local a b
  a=$(manifest_digest "$1"); b=$(manifest_digest "$2")
  [[ $a == "$b" ]] || die "digests differ: $1 $a, $2 $b"
  echo "$a"
}

repro() {
  local work a b
  # Under the checkout, not /tmp: the Docker client may not share this /tmp.
  mkdir -p "$root/bin"
  work=$(mktemp -d "$root/bin/repro.XXXXXX")
  a=passkey-auth-repro-a-$$ b=passkey-auth-repro-b-$$
  trap 'docker buildx rm -f "'"$a"'" "'"$b"'" >/dev/null 2>&1 || true; rm -rf "'"$work"'"' EXIT
  build "$work/a.tar" "$a" >/dev/null
  build "$work/b.tar" "$b" >/dev/null
  compare "$work/a.tar" "$work/b.tar"
}

size() {
  local archive=$1 digest manifest compressed=0 uncompressed=0 layer type n
  digest=$(manifest_digest "$archive")
  manifest=$(blob "$archive" "$digest")
  while read -r layer type n; do
    compressed=$((compressed + n))
    case $type in
      *+gzip) n=$(blob "$archive" "$layer" | gzip -dc | wc -c) ;;
      *+zstd) n=$(blob "$archive" "$layer" | zstd -dc | wc -c) ;;
    esac
    uncompressed=$((uncompressed + n))
  done < <(jq -r '.layers[] | "\(.digest) \(.mediaType) \(.size)"' <<<"$manifest")
  echo "compressed $compressed"
  echo "uncompressed $uncompressed"
  (( uncompressed <= MAX_BYTES )) || die "uncompressed size $uncompressed bytes is above $MAX_BYTES"
}

# load <archive>: loads the image as passkey-auth:build. The containerd image
# store loads OCI archives; the classic store needs a conversion by skopeo,
# fed through stdin so that no host path has to be visible to the daemon.
load() {
  docker load -q -i "$1" >/dev/null 2>&1 && return 0
  docker run --rm -i --entrypoint sh "$SKOPEO_IMAGE" -c \
    'cat > /tmp/oci.tar &&
     skopeo copy -q oci-archive:/tmp/oci.tar docker-archive:/tmp/docker.tar:passkey-auth:build >&2 &&
     cat /tmp/docker.tar' <"$1" | docker load -q >/dev/null
}

# smoke state, removed on exit.
smoke_name="" smoke_volume="" smoke_work=""
smoke_cleanup() {
  [[ -n $smoke_name ]] && docker rm -f "$smoke_name" >/dev/null 2>&1
  [[ -n $smoke_volume ]] && docker volume rm -f "$smoke_volume" >/dev/null 2>&1
  [[ -n $smoke_work ]] && rm -rf "$smoke_work"
  return 0
}
fail() {
  echo "image.sh: smoke: $*" >&2
  if [[ -n $smoke_name ]] && docker inspect "$smoke_name" >/dev/null 2>&1; then
    echo "image.sh: smoke: container log follows" >&2
    docker logs "$smoke_name" >&2 2>&1 || true
  fi
  exit 1
}

# run_hardened <name> [docker run args...] -- [image]: the documented hardening.
run_hardened() {
  local name=$1; shift
  docker run -d --name "$name" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
    -v "$smoke_volume:/data" \
    -e PA_RP_ID=example.com -e PA_ORIGINS=https://example.com \
    -e PA_ISSUER=https://auth.example.com -e PA_AUDIENCE=smoke \
    -e PA_SIGNING_KEY_FILE=/run/secrets/signing-key.pem \
    "$@" >/dev/null
}

# http_get <path>: the HTTP status of GET <path> on the service, body in
# $smoke_work/body. curl runs in the service's network namespace (the pinned
# skopeo image has it), so no port is published on the host.
http_get() {
  local out
  out=$(docker run --rm --network "container:$smoke_name" --entrypoint curl "$SKOPEO_IMAGE" \
    -s -m 2 -w '\n%{http_code}' "http://127.0.0.1:8080$1") || return 1
  printf '%s' "${out%$'\n'*}" >"$smoke_work/body"
  echo "${out##*$'\n'}"
}

# wait_http <path>: like http_get, once the service answers (10 s at most).
wait_http() {
  local _
  for _ in $(seq 1 20); do
    if [[ $(docker inspect -f '{{.State.Running}}' "$smoke_name") != true ]]; then
      fail "container stopped (exit $(docker inspect -f '{{.State.ExitCode}}' "$smoke_name"))"
    fi
    http_get "$1" && return 0
    sleep 0.5
  done
  fail "no answer on $1 after 10 s"
}

smoke() {
  local archive=$1 digest config id image user uid code
  digest=$(manifest_digest "$archive")
  trap smoke_cleanup EXIT
  # Under the checkout, not /tmp: a remote Docker daemon may not see /tmp.
  mkdir -p "$root/bin"
  smoke_work=$(mktemp -d "$root/bin/smoke.XXXXXX")
  smoke_volume=passkey-auth-smoke-$$
  smoke_name=passkey-auth-smoke-$$

  load "$archive" || fail "docker load failed"
  image=passkey-auth:build
  # The image ID is the manifest digest (containerd store) or the config digest.
  config=$(blob "$archive" "$digest" | jq -r .config.digest)
  id=$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null) || fail "$image not loaded"
  [[ $id == "$digest" || $id == "$config" ]] || fail "loaded image $image is $id, not $digest"

  # Non-root in the image itself, without --user.
  user=$(docker image inspect -f '{{.Config.User}}' "$image")
  [[ $user == "$IMAGE_USER" ]] || fail "image user is '$user', expected $IMAGE_USER"

  # An ephemeral key, readable by the container's user only through o+r.
  openssl genpkey -algorithm ed25519 -out "$smoke_work/signing-key.pem" 2>/dev/null
  chmod 0755 "$smoke_work"; chmod 0444 "$smoke_work/signing-key.pem"
  docker volume create "$smoke_volume" >/dev/null

  run_hardened "$smoke_name" \
    -v "$smoke_work/signing-key.pem:/run/secrets/signing-key.pem:ro" "$image"

  code=$(wait_http /v1/jwks.json)
  [[ $code == 200 ]] || fail "GET /v1/jwks.json answered $code, expected 200"
  jq -e '(.keys | length) == 1 and .keys[0].kty == "OKP" and .keys[0].crv == "Ed25519"' \
    "$smoke_work/body" >/dev/null || fail "GET /v1/jwks.json: expected one Ed25519 key, got $(head -c 300 "$smoke_work/body")"

  uid=$(docker top "$smoke_name" -o pid,uid | awk 'NR == 2 { print $2 }')
  [[ $uid == "${IMAGE_USER%%:*}" ]] || fail "process runs as uid '$uid', expected ${IMAGE_USER%%:*}"
  [[ $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$smoke_name") == true ]] \
    || fail "root filesystem is not read-only"

  docker cp "$smoke_name:/data/passkey-auth.db" - 2>/dev/null | tar -t >/dev/null 2>&1 \
    || fail "no database file /data/passkey-auth.db in the volume"

  echo "smoke: ok $digest"
}

cmd=${1:-}
[[ -n $cmd ]] && shift
case $cmd in
  build)   need 1 "$@"; build "$1" ;;
  digest)  need 1 "$@"; manifest_digest "$1" ;;
  compare) need 2 "$@"; compare "$1" "$2" ;;
  repro)   need 0 "$@"; repro ;;
  size)    need 1 "$@"; size "$1" ;;
  smoke)   need 1 "$@"; smoke "$1" ;;
  *)       usage ;;
esac
exit

return 0
