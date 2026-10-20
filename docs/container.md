# Container image

The service ships as one container image:

```
ghcr.io/criticaloptimisation/passkey-auth
```

- **Platform**: `linux/amd64`.
- **Base**: `scratch`. The image holds the static service binary, an empty
  `/data` directory for the database and an empty `/tmp` mount point. It has
  no shell, no package manager, no CA bundle and no `/etc/passwd`.
- **User**: `65532:65532`, set in the image, so the service never runs as root,
  even when `--user` is forgotten.
- **Build**: Go with `CGO_ENABLED=0` (the SQLite driver is pure Go), `-trimpath`,
  no VCS stamp, no build ID, never with the `e2e` tag: the test routes of
  [configuration.md](configuration.md#development-builds) are not in the image.

## Pulling by digest

Pin the image by its digest, never by a tag:

```sh
docker pull ghcr.io/criticaloptimisation/passkey-auth@sha256:<digest>
```

Tags exist for people only and move:

| Tag | Set by | Points to |
|---|---|---|
| `main` | every push to `main` | the latest build of `main` |
| `sha-<commit>` | every push to `main` | the build of that commit (40 hex digits) |
| `vX.Y.Z` | a published release | the build of the release tag |

The digest of each build is written in the summary of its workflow run, and,
for a release, at the end of the release notes, with the `docker pull` line and
the verification command below.

## Verifying the image

### Provenance attestation

Each published digest has a build provenance attestation, signed through
GitHub's OIDC identity of the workflow run that built it:

```sh
gh attestation verify \
  oci://ghcr.io/criticaloptimisation/passkey-auth@sha256:<digest> \
  --repo CriticalOptimisation/passkey-auth
```

It succeeds only if the digest was built by a workflow of this repository, and
it names the commit and the workflow run. The attestation is stored by GitHub
and pushed to the registry next to the image; it does not change the image's
digest.

### Rebuilding the same digest

Anyone can rebuild a commit and get the published digest, with Docker only:

```sh
git clone https://github.com/CriticalOptimisation/passkey-auth.git
cd passkey-auth
git checkout <commit>
tools/image.sh build /tmp/passkey-auth.tar     # prints sha256:<digest>
```

**"Same digest" means the image manifest digest**, the one consumers pin and
`docker pull` prints. BuildKit's own provenance and SBOM attestations are
turned off for every build, the published one included, because they record
the build time and would change the digest of each build. Provenance is carried
by the GitHub attestation above instead.

What makes two builds of one commit identical:

| Input | How it is fixed |
|---|---|
| Go toolchain and build stage | `golang` image pinned by digest, `GOTOOLCHAIN=local` |
| Go modules | verified against `go.sum`, `-mod=readonly` |
| BuildKit | `moby/buildkit` pinned by digest in `tools/image.sh`, which creates its own builder |
| Time stamps | `SOURCE_DATE_EPOCH` = commit time; layer files rewritten to it (`rewrite-timestamp=true`) |
| File modes and owners | set explicitly in the final stage, never taken from the checkout |
| Binary | `-trimpath -buildvcs=false -ldflags='-s -w -buildid='` |
| Labels | `org.opencontainers.image.source`, `.revision` (the commit), `.licenses`; no `created` label |

The build context is the working tree: `tools/image.sh build` warns when the
files that enter the image have uncommitted changes, since the digest is then
not that of the commit.

## Running the container

The service is always deployed behind a reverse proxy that terminates TLS; see
[configuration.md](configuration.md#behind-traefik) for the Traefik labels and
for every `PA_*` variable.

### Hardening

| Setting | `docker run` | Why |
|---|---|---|
| Read-only root filesystem | `--read-only` | the service writes only to its database |
| Non-root | built in (`65532:65532`) | no root process to escape with |
| No capabilities | `--cap-drop ALL` | the service listens on an unprivileged port and needs none |
| No privilege gain | `--security-opt no-new-privileges` | blocks set-uid escalation |
| Temporary files | `--tmpfs /tmp:size=16m,noexec,nosuid,nodev` | SQLite may need a temporary directory; nothing else is writable |
| Database | `-v passkey-auth-data:/data` (named volume) | credentials survive upgrades; a new named volume takes the owner of the image's `/data` (`65532`, mode `0700`) |
| Signing key | a file mounted read-only, e.g. at `/run/secrets/signing-key.pem`, named by `PA_SIGNING_KEY_FILE` | the only secret, never in the image or the database |

### Signing key

Generate the key as in [configuration.md](configuration.md#signing-key). The
container runs as uid `65532`, so the mounted file must be readable by that
user, and by no one else on the host:

```sh
openssl genpkey -algorithm ed25519 -out signing-key.pem
sudo chown 65532:65532 signing-key.pem
sudo chmod 0400 signing-key.pem
```

### `docker run`

```sh
docker run -d --name passkey-auth \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:size=16m,noexec,nosuid,nodev \
  -v passkey-auth-data:/data \
  -v "$PWD/signing-key.pem:/run/secrets/signing-key.pem:ro" \
  -e PA_RP_ID=example.com \
  -e PA_ORIGINS=https://example.com \
  -e PA_ISSUER=https://auth.example.com \
  -e PA_AUDIENCE=example-host \
  -e PA_SIGNING_KEY_FILE=/run/secrets/signing-key.pem \
  ghcr.io/criticaloptimisation/passkey-auth@sha256:<digest>
```

### Compose

```yaml
services:
  passkey-auth:
    image: ghcr.io/criticaloptimisation/passkey-auth@sha256:<digest>
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs:
      - /tmp:size=16m,noexec,nosuid,nodev
    volumes:
      - passkey-auth-data:/data
      - ./signing-key.pem:/run/secrets/signing-key.pem:ro
    environment:
      PA_RP_ID: example.com
      PA_ORIGINS: https://example.com
      PA_ISSUER: https://auth.example.com
      PA_AUDIENCE: example-host
      PA_SIGNING_KEY_FILE: /run/secrets/signing-key.pem
    # Traefik labels: see docs/configuration.md, "Behind Traefik".
    restart: unless-stopped

volumes:
  passkey-auth-data:
```

### Health

The image has no shell and no client, so it declares no `HEALTHCHECK`. Check it
from outside, through the proxy or the container network: `GET /v1/jwks.json`
answers `200` only once the configuration, the signing key and the database
have loaded. A container whose configuration is invalid exits at once with a
non-zero status and one JSON log line naming the variable at fault.

## Building and checking: `tools/image.sh`

The CI workflow and the maintainer run the same script. It needs Docker with
buildx, `git`, `jq`, `curl` and `openssl`; no Go installation.

| Command | Does | Exit status |
|---|---|---|
| `tools/image.sh build <out.tar>` | builds the image of the working tree into an OCI archive, with the settings above; prints its image manifest digest | `0` built; `1` build failed |
| `tools/image.sh digest <archive>` | prints the image manifest digest of an archive | `0`; `1` not a single-image OCI archive |
| `tools/image.sh compare <a.tar> <b.tar>` | compares the digests of two archives | `0` equal; `1` different |
| `tools/image.sh repro` | two builds, each on a new builder and without cache, then `compare` | `0` reproducible; `1` not |
| `tools/image.sh size <archive>` | prints `compressed <bytes>` (what a pull downloads) and `uncompressed <bytes>` | `0`; `1` uncompressed size above 30 MB (30 000 000 bytes) |
| `tools/image.sh smoke <archive>` | loads the image and runs it hardened (below) | `0` all checks passed; `1` a check failed |

Usage errors exit with `2`. Diagnostics go to standard error, one line each,
starting with `image.sh:`.

`smoke` checks, on a fresh named volume and with a key generated for the test:

- the image's user is `65532:65532`;
- the container starts with `--read-only --cap-drop ALL --security-opt
  no-new-privileges` and a tmpfs on `/tmp`, and its process runs as uid 65532;
- `GET /v1/jwks.json` answers `200` with one Ed25519 key;
- the database file `/data/passkey-auth.db` was created in the volume;
- `GET /test/` answers `404`: the image carries no test route;
- the image has no shell;
- without its signing key, the container exits non-zero and logs
  `PA_SIGNING_KEY_FILE`;
- after a restart on the same volume, the database is still there.

## Publication

The workflow `.github/workflows/image.yml` runs on every pull request, on every
push to `main`, on a manual dispatch and on every published release:

1. two builds of the commit, on two separate runners, without cache;
2. `compare` of their digests, and the sizes, in the run summary; the run fails
   if the digests differ or the image exceeds 30 MB;
3. `smoke` on the first build;
4. on `main` and for releases only, never on a pull request: the archive that
   passed these checks is pushed as is (its digest is checked again in the
   registry), attested, and the attestation verified with
   `gh attestation verify`;
5. for a release: the digest is appended to the release notes.

The GHCR package is public, so pulling needs no credentials.
