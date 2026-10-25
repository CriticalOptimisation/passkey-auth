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
#   tools/image.sh push <archive> <repository> <tag>...
#                                         pushes the archive as is; token on stdin
#   tools/image.sh pins [<reference>...]  exit 1 unless every pinned image keeps the rule
#
# Exit status: 0 success, 1 a check or a build failed, 2 usage error.
set -euo pipefail

readonly BUILDKIT_IMAGE=moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3
# The plain version tags of quay.io/skopeo/stable are rebuilt every day, and
# the index they pointed to soon stops being served (#17): only the -immutable
# tag keeps its digest. A newer version changes both the tag and the digest.
readonly SKOPEO_IMAGE=quay.io/skopeo/stable:v1.22.3-immutable@sha256:c0ee1f4edca5c01cb8d5611124f92f3cc47196ecab68aee5d0f90834e00574d5
readonly PLATFORM=linux/amd64
readonly IMAGE_USER=65532:65532
readonly MAX_BYTES=30000000
readonly MANIFEST_TYPE=application/vnd.oci.image.manifest.v1+json
# Files that enter the image (see .dockerignore).
readonly CONTEXT_PATHS=(Dockerfile .dockerignore go.mod go.sum cmd internal web)
# Images of the containers project (podman, buildah, skopeo): their version
# tags are rebuilt every day and the old index is soon no longer served; only
# their -immutable tags are never overwritten (#17, docs/container.md).
readonly CONTAINERS_PROJECT='^quay\.io/(containers/(podman|buildah|skopeo)|(podman|buildah|skopeo)/stable)$'

root=$(git rev-parse --show-toplevel)

die() { echo "image.sh: $*" >&2; exit 1; }
usage() {
  echo "usage: tools/image.sh build <out.tar> | digest <archive> | compare <a.tar> <b.tar> | repro | size <archive> | smoke <archive> | push <archive> <repository> <tag>... | pins [<reference>...]" >&2
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

# smoke state, removed on exit. smoke_name is the container under check.
smoke_name="" smoke_volume="" smoke_work="" smoke_containers=()
smoke_cleanup() {
  local c
  for c in "${smoke_containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done
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
  smoke_name=$name smoke_containers+=("$name")
  docker run -d --name "$name" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
    -v "$smoke_volume:/data" \
    -e PA_RP_ID=example.com -e PA_ORIGINS=https://example.com \
    -e PA_ISSUER=https://auth.example.com -e PA_AUDIENCE=smoke \
    -e PA_HOST_DID=did:web:example.com \
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

  local key=$smoke_work/signing-key.pem:/run/secrets/signing-key.pem:ro
  run_hardened "passkey-auth-smoke-$$" -v "$key" "$image"

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

  # The e2e build tag never reaches the image: no test route.
  code=$(http_get /test/) || fail "GET /test/: no answer"
  [[ $code == 404 ]] || fail "GET /test/ answered $code, expected 404"

  # No shell: docker run answers 127 when the entrypoint does not exist.
  code=0
  docker run --rm --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1 || code=$?
  [[ $code == 127 ]] || fail "--entrypoint /bin/sh exited $code, expected 127 (no shell)"

  # A restart on the same volume, as an upgrade does, keeps the database file.
  local inode
  inode=$(db_inode) || fail "cannot stat /data/passkey-auth.db in the volume"
  docker stop -t 10 "$smoke_name" >/dev/null
  code=$(docker inspect -f '{{.State.ExitCode}}' "$smoke_name")
  [[ $code == 0 ]] || fail "after SIGTERM, the container exited $code, expected 0"
  docker rm "$smoke_name" >/dev/null
  run_hardened "passkey-auth-smoke-$$-restart" -v "$key" "$image"
  code=$(wait_http /v1/jwks.json)
  [[ $code == 200 ]] || fail "after a restart, GET /v1/jwks.json answered $code, expected 200"
  [[ $(db_inode) == "$inode" ]] || fail "after a restart, /data/passkey-auth.db is not the same file"
  docker rm -f "$smoke_name" >/dev/null

  # Without its signing key, the container stops at once and says why.
  run_hardened "passkey-auth-smoke-$$-nokey" "$image"
  code=$(timeout 10 docker wait "$smoke_name") || fail "without a signing key, still running after 10 s"
  [[ $code != 0 ]] || fail "without a signing key, the container exited 0"
  docker logs "$smoke_name" 2>&1 | grep -q PA_SIGNING_KEY_FILE \
    || fail "without a signing key, the log does not name PA_SIGNING_KEY_FILE"

  echo "smoke: ok $digest"
}

# db_inode: the inode of the database file in the smoke volume, read by the
# pinned skopeo image, which has a shell (the service image has none).
db_inode() {
  docker run --rm -v "$smoke_volume:/data:ro" --entrypoint stat "$SKOPEO_IMAGE" \
    -c %i /data/passkey-auth.db
}

# push <archive> <repository> <tag>...: pushes the archive under each tag,
# digests preserved, then checks that the registry serves the archive's digest
# under every tag, and prints it. The token is read from stdin and the user from
# REGISTRY_USER; the token reaches skopeo on its stdin, never in an argument or
# in the container's environment.
push() {
  local archive=$1 repo=$2 digest token out tag got; shift 2
  digest=$(manifest_digest "$archive")
  [[ -n ${REGISTRY_USER:-} ]] || die "push: REGISTRY_USER is not set"
  IFS= read -r token || [[ -n $token ]] || die "push: no registry token on stdin"
  [[ -n $token ]] || die "push: empty registry token on stdin"
  out=$({ printf '%s\n' "$token"; cat "$archive"; } |
    docker run --rm -i -e REGISTRY_USER --entrypoint sh "$SKOPEO_IMAGE" -c '
      set -e
      IFS= read -r token
      cat > /tmp/oci.tar
      repo=$1; shift
      printf "%s" "$token" | skopeo login -u "$REGISTRY_USER" --password-stdin "${repo%%/*}" >&2
      for tag; do
        skopeo copy -q --preserve-digests oci-archive:/tmp/oci.tar "docker://$repo:$tag" >&2
        echo "$tag sha256:$(skopeo inspect --raw "docker://$repo:$tag" | sha256sum | cut -d" " -f1)"
      done' sh "$repo" "$@") || die "push: push to $repo failed"
  while read -r tag got; do
    [[ $got == "$digest" ]] || die "push: $repo:$tag is $got in the registry, not $digest"
  done <<<"$out"
  echo "$digest"
}

# pins [<reference>...]: checks each reference (by default the script's own
# pinned images): a tag and a sha256 digest; an -immutable tag for an image of
# the containers project. Every reference is checked; exit 1 if one fails.
pins() {
  local ref repo tag status=0
  [[ $# -gt 0 ]] || set -- "$BUILDKIT_IMAGE" "$SKOPEO_IMAGE"
  for ref; do [[ $ref != -* ]] || usage; done
  for ref; do
    if [[ ! $ref =~ ^([^@]+):([^:@/]+)@sha256:[0-9a-f]{64}$ ]]; then
      echo "image.sh: pins: $ref: not pinned by digest" >&2; status=1; continue
    fi
    repo=${BASH_REMATCH[1]} tag=${BASH_REMATCH[2]}
    if [[ $repo =~ $CONTAINERS_PROJECT && $tag != *-immutable ]]; then
      echo "image.sh: pins: $ref: image of the containers project without an -immutable tag" >&2
      status=1; continue
    fi
    echo "ok $ref"
  done
  return "$status"
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
  push)    [[ $# -ge 3 ]] || usage; push "$@" ;;
  pins)    pins "$@" ;;
  *)       usage ;;
esac
exit

return 0

# --- Change History -------------------------------------------------------
# | PR     | Summary                                                       |
# |--------|---------------------------------------------------------------|
# | #15    | build, check, smoke and push the container image              |
# | #14    | smoke run sets the required PA_HOST_DID                       |
# | #19    | skopeo pinned on its -immutable tag; pins subcommand          |
