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
material.

## Development builds

Building with `-tags e2e` adds two routes used by the end-to-end tests and
nowhere else:

- `POST /test/tickets` with `{"account": "...", "displayName": "..."}` returns
  `{"ticket": "..."}`, a registration ticket, standing in for the host-facing
  API of issue #5;
- `GET /test/` returns a blank HTML page on the service's origin, from which
  the tests import the browser helper.

Release builds never carry this tag.
