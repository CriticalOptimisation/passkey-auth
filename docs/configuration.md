# Configuration

`passkey-auth` is configured through environment variables only. It checks the
whole configuration at startup and exits with a non-zero status, naming the
faulty variable, if anything is missing or invalid.

## Variables

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `PA_LISTEN` | no | `:8080` | listen address, plain HTTP (TLS is terminated by the reverse proxy) |
| `PA_RP_ID` | **yes** | | WebAuthn RP ID: the host's registrable domain, e.g. `example.com` |
| `PA_RP_NAME` | no | value of `PA_RP_ID` | name shown by some authenticators |
| `PA_ORIGINS` | **yes** | | comma-separated list of allowed origins, compared exactly, e.g. `https://example.com,https://www.example.com` |
| `PA_ISSUER` | **yes** | | `iss` of result tokens, normally the public URL of the service |
| `PA_AUDIENCE` | **yes** | | `aud` of result tokens: an identifier of the host |
| `PA_SIGNING_KEY_FILE` | **yes** | | path of the Ed25519 private key, PKCS#8 PEM |
| `PA_PREVIOUS_SIGNING_KEY_FILE` | no | | path of the previous Ed25519 key (PKCS#8 private or SPKI public PEM), published in the JWKS during a rotation |
| `PA_DB_PATH` | no | `/data/passkey-auth.db` | SQLite database file; its directory must be writable |
| `PA_CHALLENGE_TTL` | no | `5m` | validity of a ceremony challenge, Go duration syntax |
| `PA_TICKET_TTL` | no | `15m` | validity of a registration ticket |
| `PA_TOKEN_TTL` | no | `60s` | lifetime of a result token |
| `PA_MAX_CHALLENGES` | no | `100000` | live challenges above which `options` answers `503 unavailable` |

Validation rules:

- every origin of `PA_ORIGINS` is `scheme://host[:port]` with no path;
  `https` is required, except for `http://localhost` and `http://127.0.0.1`
  with any port (development and tests);
- an origin whose host is not `PA_RP_ID` or one of its subdomains is accepted
  with a warning in the log: it only works once Related Origin Requests are
  configured on the RP ID's domain (see [api.md](api.md#cross-origin-access));
- durations are positive; `PA_TOKEN_TTL` is at most `5m`.

## Signing key

The result-signing key is the only secret of the service. It is never stored in
the database nor in the image: mount it as a container secret.

```sh
openssl genpkey -algorithm ed25519 -out signing-key.pem
```

The key ID (`kid`) is the RFC 7638 thumbprint of the public key, so it needs no
configuration.

**Rotation.** Generate a new key, set `PA_SIGNING_KEY_FILE` to it and
`PA_PREVIOUS_SIGNING_KEY_FILE` to the old one, restart, then remove
`PA_PREVIOUS_SIGNING_KEY_FILE` once every host has refreshed its JWKS cache
(5 minutes plus the token lifetime is enough).

## Storage

The database holds public material only (see
[api.md](api.md#security-properties)). Put it on a named volume so that
credentials survive container upgrades. One deployment uses one database file;
running several replicas needs another storage backend.

## Logs

Structured JSON on standard output: one line per request, plus the reason of
every rejected ceremony. Logs carry no challenge, ticket, token or key
material, and no IP address or account reference (see the GDPR section of the
README). The reverse proxy's own logs are the operator's responsibility.

## Behind Traefik

The service speaks plain HTTP and is always deployed behind a reverse proxy.
The examples use Traefik v3 with the Docker provider. Configuration goes in
the container's own labels.

### Transport security

- **Within one machine, plain HTTP is allowed.** Traefik reaches the service
  over a Docker network on the same machine, and a host application running on
  that same machine may call the service directly.
- **On the LAN or the Internet, TLS is mandatory.** Every connection that leaves
  the machine goes through Traefik, which terminates TLS. The service publishes
  no port, so nothing else can reach it from outside the machine.

Calls that stay on the machine are not trusted for that reason alone. A
browser ceremony is protected by WebAuthn, whatever the path of the request.
The host-facing routes (#5) authenticate every request in the service itself,
because any container on the shared Docker network can reach the service
without going through Traefik.

### Listeners

| Listener | Variable | Routes | Traefik entry point |
|---|---|---|---|
| public | `PA_LISTEN` (`:8080`) | ceremonies, JWKS, browser helper | the Internet-facing HTTPS entry point (`websecure`) |
| host | `PA_HOST_LISTEN` (issue #5) | tickets and credential management | an entry point bound to the private network only, with TLS |

The two route families never share a listener. If a public routing rule is
too broad, it can still only reach the public listener, so it cannot expose
the host-facing routes.

### Public router

Example labels: the service under `/auth` on the host's own domain. Router and
middleware names are global to a Traefik instance, so prefix them.

**How Traefik picks a router.** Among the routers whose rule matches a
request, Traefik takes the one with the **highest priority**. It is not the
first or the last one declared. A router without an explicit priority gets the
length of its rule string as its priority. The routers below set their
priorities explicitly, so the result does not depend on how long the rules
are.

| Request | Router | Middlewares, in order |
|---|---|---|
| `POST /auth/v1/registration/options`, `POST /auth/v1/authentication/options` | `pa-options` (priority 200) | strip `/auth`, global ceiling, per-IP limit for ceremony starts, per-IP concurrency, security headers |
| any other path under `/auth/`: the `verify` routes, JWKS, helper, unknown paths | `pa-public` (priority 100) | strip `/auth`, global ceiling, per-IP limit, per-IP concurrency, security headers |

**Every route is rate-limited**, including paths the service does not know.
There are three limits:

- **a per-IP limit on every route** (`pa-rl-ip`);
- **a tighter per-IP limit on ceremony starts** (`pa-rl-options`). An anonymous
  caller can create challenges there;
- **a global ceiling** (`pa-rl-global`). All callers share one bucket
  (`sourcecriterion.requesthost`), so a flood spread over many addresses is
  capped too. When the ceiling is reached, legitimate users are refused (429)
  as well: that is the price of protecting the service.

A request that exceeds a limit gets `429 Too Many Requests` from Traefik and
never reaches the service. The limits are kept in memory by each Traefik
instance.

```
traefik.enable=true
traefik.http.services.pa-public.loadbalancer.server.port=8080

traefik.http.routers.pa-public.rule=Host(`example.com`) && PathPrefix(`/auth/`)
traefik.http.routers.pa-public.priority=100
traefik.http.routers.pa-public.entrypoints=websecure
traefik.http.routers.pa-public.tls=true
traefik.http.routers.pa-public.middlewares=pa-strip,pa-rl-global,pa-rl-ip,pa-inflight,pa-headers
traefik.http.routers.pa-public.service=pa-public

traefik.http.routers.pa-options.rule=Host(`example.com`) && Method(`POST`) && PathRegexp(`^/auth/v1/(registration|authentication)/options$`)
traefik.http.routers.pa-options.priority=200
traefik.http.routers.pa-options.entrypoints=websecure
traefik.http.routers.pa-options.tls=true
traefik.http.routers.pa-options.middlewares=pa-strip,pa-rl-global,pa-rl-options,pa-inflight,pa-headers
traefik.http.routers.pa-options.service=pa-public

traefik.http.middlewares.pa-strip.stripprefix.prefixes=/auth

# Global ceiling: one bucket for all callers.
traefik.http.middlewares.pa-rl-global.ratelimit.average=50
traefik.http.middlewares.pa-rl-global.ratelimit.period=1s
traefik.http.middlewares.pa-rl-global.ratelimit.burst=100
traefik.http.middlewares.pa-rl-global.ratelimit.sourcecriterion.requesthost=true

# Per source IP, every route.
traefik.http.middlewares.pa-rl-ip.ratelimit.average=60
traefik.http.middlewares.pa-rl-ip.ratelimit.period=1m
traefik.http.middlewares.pa-rl-ip.ratelimit.burst=30
traefik.http.middlewares.pa-rl-ip.ratelimit.sourcecriterion.ipstrategy.depth=0

# Per source IP, ceremony starts only.
traefik.http.middlewares.pa-rl-options.ratelimit.average=20
traefik.http.middlewares.pa-rl-options.ratelimit.period=1m
traefik.http.middlewares.pa-rl-options.ratelimit.burst=10
traefik.http.middlewares.pa-rl-options.ratelimit.sourcecriterion.ipstrategy.depth=0

traefik.http.middlewares.pa-inflight.inflightreq.amount=10
traefik.http.middlewares.pa-inflight.inflightreq.sourcecriterion.ipstrategy.depth=0

traefik.http.middlewares.pa-headers.headers.stsseconds=31536000
traefik.http.middlewares.pa-headers.headers.contenttypenosniff=true
traefik.http.middlewares.pa-headers.headers.framedeny=true
```

- **Values.** These are a starting point, to be tuned from real traffic. One
  login uses two requests (`options`, then `verify`), plus the helper and the
  JWKS, both of which are cached.
- **`ipstrategy.depth=0`.** It takes the address of the TCP connection, which
  is right when Traefik faces the Internet directly. Behind a CDN or a load
  balancer, set `depth` or `excludedips` instead, or every user will share the
  CDN's address.
- **Prefix.** The browser helper loaded from the service derives its base URL
  from its own location, so the `/auth` prefix needs no setting in the service.
  `PA_ISSUER` should be the public URL, including the prefix.

### Defences in the service itself

Traefik's limits bound the request rate. Two things in the service keep each
request cheap:

- **Cheap checks first.** A `verify` request is refused before any signature
  verification if:
  - its body is over 64 KiB, not JSON, or has an unknown field;
  - its `clientDataJSON` is malformed;
  - its challenge is unknown, expired or already used.

  So a flood of invented responses costs one JSON decode and one indexed
  lookup each.
- **Bounded state.** Expired challenges and tickets are purged. Above
  `PA_MAX_CHALLENGES` live challenges, `options` answers `503` with code `unavailable`,
  so the database cannot be filled faster than the purge empties it.

### Who does what

| Traefik | Service |
|---|---|
| TLS termination and certificates | WebAuthn checks, including the origin check on `clientDataJSON` |
| rate limits (per IP and global), in-flight limits, on every route | cheap checks before cryptography; the challenge TTL, purge and cap; the 64 KiB body limit |
| HSTS, `nosniff`, frame denial | CORS on the ceremony routes. Its allow-list is `PA_ORIGINS`, the list WebAuthn checks, so a second list kept in Traefik could drift from it. |
| IP allow-list on the host entry point (#5) | authentication of the host on every host-facing request (#5) |
| | the usage log of the browser helper |

## Development builds

Building with `-tags e2e` adds two routes used by the end-to-end tests and
nowhere else:

- `POST /test/tickets` with `{"account": "...", "displayName": "..."}` returns
  `{"ticket": "..."}`, a registration ticket, standing in for the host-facing
  API of issue #5;
- `GET /test/` returns a blank HTML page on the service's origin, from which
  the tests import the browser helper.

Release builds never carry this tag.
