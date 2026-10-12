# API contract

This document is the contract between `passkey-auth`, the browsers that run
the WebAuthn ceremonies, and the host application that trusts the result. It is
written before the implementation; the tests illustrate it.

- [Overview](#overview)
- [Conventions](#conventions)
- [Registration](#registration)
- [Authentication](#authentication)
- [Origin check](#origin-check)
- [Result token](#result-token)
- [Keys](#keys)
- [Browser helper](#browser-helper)
- [Cross-origin access](#cross-origin-access)
- [Errors](#errors)
- [Security properties](#security-properties)

## Overview

`passkey-auth` proves that the person in front of a browser holds an
authenticator bound to an account of the host application. It is not an
identity provider and keeps no session:

1. The host decides who may register a passkey for an account and obtains a
   one-time **registration ticket** for it (host-facing API, issue #5).
2. The browser runs a ceremony against the browser-facing routes below, usually
   through the [browser helper](#browser-helper).
3. The service answers a successful ceremony with a short-lived **result
   token**, signed with Ed25519.
4. The browser hands the token to the host backend, which verifies it with the
   published [JWKS](#keys) and opens its own session.

```
browser                         passkey-auth                      host backend
   | POST /v1/authentication/options {nonce}  |                        |
   |----------------------------------------->|                        |
   |<------------------- {publicKey: ...} ----|                        |
   | navigator.credentials.get()              |                        |
   | POST /v1/authentication/verify           |                        |
   |----------------------------------------->|                        |
   |<--------------------------- {token} -----|                        |
   | token ------------------------------------------------------------>|
   |                                          |<-- GET /.well-known/jwks.json (cached)
```

**Topology.** One deployment serves one relying party (RP ID). The RP ID is the
host's registrable domain (for example `example.com`), and the service is
reached on the same site, under a path prefix routed by the host's reverse
proxy or on a sibling subdomain. The browser-facing routes are relative to the
service root; a prefix stripped by the proxy is invisible to the service.

The set of allowed origins (`PA_ORIGINS`) is an explicit list. It may contain
origins outside the RP ID's domain, so that WebAuthn Related Origin Requests
can be enabled later without changing this contract (see
[Cross-origin access](#cross-origin-access)). Use from arbitrary third-party
domains through an embedded frame is issue #10.

## Conventions

- Requests and responses are JSON (`Content-Type: application/json`), UTF-8.
- Binary values are **base64url without padding**, as in the WebAuthn Level 3
  JSON serialisation.
- Request bodies are limited to 64 KiB. Unknown fields are rejected; every
  field of the WebAuthn Level 3 JSON serialisation is known, including
  `response.authenticatorData`, `response.publicKey` and
  `response.publicKeyAlgorithm`, which browsers add to registration responses.
- WebAuthn options are returned in the form expected by
  `PublicKeyCredential.parseCreationOptionsFromJSON()` and
  `parseRequestOptionsFromJSON()`, wrapped in a `publicKey` member.
- Credentials are posted in the form produced by `PublicKeyCredential.toJSON()`.
- Times in tokens are seconds since the Unix epoch.

## Registration

A registration ticket is created by the host for one account and one display
name. It is valid for `PA_TICKET_TTL` (default 15 minutes) and is **consumed by
`/v1/registration/options`**: if the ceremony then fails or is abandoned, the
host issues a new ticket.

The first registration of an account creates its **user handle**: 64 random
bytes, used as the WebAuthn `user.id`. The host's account reference never
reaches the authenticator. The display name is kept only in the ticket: it is
sent to the authenticator in the options, then deleted with the ticket.

**Registration only ever adds a credential.** It never removes or replaces
one. A ceremony that fails at any step, a lost connection or an expired
ticket included, costs only the ticket: credentials already registered keep
working. To replace an authenticator, the host registers the new one first and
revokes the old one (host-facing API, #5) only after the new registration
token has arrived.

### `POST /v1/registration/options`

Request:

```json
{ "ticket": "<opaque ticket string>" }
```

Response `200`:

```json
{
  "publicKey": {
    "rp": { "id": "example.com", "name": "Example" },
    "user": { "id": "<user handle>", "name": "<display name>", "displayName": "<display name>" },
    "challenge": "<32 random bytes>",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -8 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 300000,
    "excludeCredentials": [ { "type": "public-key", "id": "<credential ID>" } ],
    "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
    "attestation": "direct"
  }
}
```

- `excludeCredentials` lists the credentials already registered for the
  account, so the same authenticator is not registered twice.
- `timeout` equals `PA_CHALLENGE_TTL` in milliseconds.
- Errors: `ticket_invalid` (unknown, expired or already used ticket),
  `invalid_request`.

### `POST /v1/registration/verify`

Request: the `RegistrationResponseJSON` of the new credential.

```json
{
  "id": "<credential ID>",
  "rawId": "<credential ID>",
  "type": "public-key",
  "response": {
    "clientDataJSON": "<...>",
    "attestationObject": "<...>",
    "transports": ["usb"]
  },
  "authenticatorAttachment": "cross-platform",
  "clientExtensionResults": {}
}
```

Response `200`:

```json
{ "token": "<result token, ceremony = registration>" }
```

The service checks the challenge (known, unused, unexpired, issued for a
registration), the type, the [origin](#origin-check), the RP ID hash, the user-present and
user-verified flags, the algorithm and, when present, the attestation
statement. It stores the credential and returns a [result token](#result-token).

Attestation is requested and recorded (format and AAGUID) but not required:
synced passkeys usually return none. An attestation policy is issue #9.

Errors: `challenge_invalid`, `verification_failed`, `invalid_request`.

## Authentication

Authentication uses **discoverable credentials**: the options carry no
`allowCredentials`, so the service never discloses which credentials exist.
Conditional mediation (passkey autofill) is supported by the browser helper.

The host supplies a **nonce** for every authentication. The nonce is echoed in
the result token; the host checks it to bind the token to its own login
attempt.

### `POST /v1/authentication/options`

Request:

```json
{ "nonce": "<base64url, 16 to 64 bytes once decoded>" }
```

Response `200`:

```json
{
  "publicKey": {
    "challenge": "<32 random bytes>",
    "timeout": 300000,
    "rpId": "example.com",
    "allowCredentials": [],
    "userVerification": "required"
  }
}
```

Errors: `invalid_request` (missing or malformed nonce).

### `POST /v1/authentication/verify`

Request: the `AuthenticationResponseJSON` of the assertion.

```json
{
  "id": "<credential ID>",
  "rawId": "<credential ID>",
  "type": "public-key",
  "response": {
    "clientDataJSON": "<...>",
    "authenticatorData": "<...>",
    "signature": "<...>",
    "userHandle": "<user handle>"
  },
  "authenticatorAttachment": "platform",
  "clientExtensionResults": {}
}
```

Response `200`:

```json
{ "token": "<result token, ceremony = authentication>" }
```

The service checks the challenge (known, unused, unexpired, issued for an
authentication), the type, the [origin](#origin-check), the RP ID hash, the user-present and
user-verified flags, the credential (known, and belonging to `userHandle`), the
signature, and the **signature counter**:

| Stored counter | Counter received | Result |
|---|---|---|
| 0 | 0 | accepted (synced passkeys never count) |
| any | greater than stored | accepted, counter updated |
| greater than 0 | equal or lower | **rejected** (possible cloned authenticator) |

On success the counter, the backup flags and the last-used time are updated.

Errors: `challenge_invalid`, `credential_unknown`, `verification_failed`,
`invalid_request`.

## Origin check

The origin is the security check that defeats phishing, so its rules are
exact:

- **`PA_ORIGINS` is normalised once, at startup.** Scheme and host are
  lowercased, and a default port (`:443` for `https`, `:80` for `http`) is
  removed. A trailing `/` is dropped. Anything else is refused at startup: a
  path, query, fragment or user info; a percent-encoded character; or a host
  that is not ASCII. Internationalised domain names are written in their
  punycode form (`xn--...`), so the service needs no IDNA library.
- **The `origin` of `clientDataJSON` is not normalised.** The browser writes it
  in exactly that canonical form (the ASCII serialisation of the origin in the
  HTML standard). It is compared **byte for byte** with the normalised list. A
  value in any other form did not come from a conforming browser and is
  rejected.
- `clientDataJSON.crossOrigin` must be absent or `false`, and `topOrigin` must
  be absent: a ceremony run inside a cross-origin frame is rejected. The
  embedded frame of #10 will change this rule, and only for its own origin.

## Result token

A compact JWS (JWT) signed with Ed25519.

Header:

| Field | Value |
|---|---|
| `alg` | `EdDSA` |
| `typ` | `passkey-result+jwt` |
| `kid` | key ID, listed in the JWKS |

Claims:

| Claim | Ceremony | Meaning |
|---|---|---|
| `iss` | both | `PA_ISSUER` |
| `aud` | both | `PA_AUDIENCE`, the host |
| `sub` | both | the host's account reference |
| `iat`, `exp` | both | issue and expiry time; `exp - iat` = `PA_TOKEN_TTL` (default 60 s) |
| `jti` | both | unique token ID (16 random bytes, base64url) |
| `ceremony` | both | `registration` or `authentication` |
| `origin` | both | origin of the page that ran the ceremony, as verified in `clientDataJSON` |
| `cred` | both | credential ID, base64url |
| `uv` | both | user verified (always `true`, since verification is required) |
| `be` | both | backup eligible: the credential can be synced |
| `bs` | both | backup state: the credential is currently synced |
| `nonce` | authentication | the host nonce, as received |
| `assurance` | both | profile of the credential: `passkey`, or `attested-hardware` once its attestation meets the policy of #9; see [security.md](security.md#assurance-profiles). Until #9, always `passkey`. |
| `aaguid` | both | authenticator model, UUID string (all zeros when unknown) |
| `fmt` | registration | attestation format (`none`, `packed`, ...) |

**Verifying a token (host backend).** The host must:

1. fetch the JWKS (cache it; refetch on an unknown `kid`);
2. check `alg` = `EdDSA`, `typ` = `passkey-result+jwt`, and the signature with
   the key named by `kid`;
3. check `iss`, `aud` (its own), and `exp` (allowing a few seconds of clock
   skew);
4. check `ceremony`; for an authentication, check that `nonce` is the one it
   issued for this login attempt and has not been used before;
5. grant rights according to `assurance`;
6. when several applications share a deployment, check `origin`.

The token is accepted once: the host may record `jti` until `exp`.

## Keys

### `GET /.well-known/jwks.json`

Response `200`, `Cache-Control: public, max-age=300`,
`Access-Control-Allow-Origin: *`:

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "<public key>", "kid": "<key ID>", "use": "sig", "alg": "EdDSA" }
  ]
}
```

The current signing key comes first. During a rotation, the previous public key
(`PA_PREVIOUS_SIGNING_KEY_FILE`) is listed after it, so tokens signed before the
switch still verify. The `kid` is the RFC 7638 thumbprint of the public key.

## Browser helper

### `GET /v1/passkey-auth.js`

An ES module, served with `Content-Type: text/javascript`,
`Access-Control-Allow-Origin: *` and `Cross-Origin-Resource-Policy:
cross-origin`, so that pages on any domain may load it. It holds no secret and
is not part of the security boundary: it may also be bundled with the host's
own scripts. The service logs each load of the helper (requesting origin and
helper version only), as a usage metric.

**Where the helper sends its requests.** Every function takes an optional
`baseURL`: the service root, under which the routes `v1/...` are resolved.

- When the helper is **loaded from the service** (`import ... from
  "https://example.com/auth/v1/passkey-auth.js"`), `baseURL` defaults to the
  service root derived from the module's own URL (`new URL("..",
  import.meta.url)`). A path prefix set by the reverse proxy then needs no
  configuration.
- When the helper is **bundled** with the host's scripts, the module's URL is
  the bundle's, and the default is meaningless: the host must pass `baseURL`.
  Minification keeps what the host relies on: the exported names, the
  `baseURL` option, and the route paths and JSON shapes of this contract.

When `baseURL` is on another origin than the page, the ceremony routes answer
only if the page's origin is in `PA_ORIGINS` (see
[Cross-origin access](#cross-origin-access)).

```js
import { register, authenticate, PasskeyAuthError } from "/auth/v1/passkey-auth.js";

// Registration, with a ticket obtained from the host backend.
const token = await register(ticket);

// Authentication, with a nonce obtained from the host backend.
const token = await authenticate(nonce);

// Passkey autofill: requires <input autocomplete="username webauthn">.
const token = await authenticate(nonce, { conditional: true, signal });

// Bundled helper: name the service root explicitly.
const token = await authenticate(nonce, { baseURL: "https://example.com/auth/" });
```

Both functions resolve to the result token, a string, which the page sends to
its backend. They reject with a `PasskeyAuthError` whose `code` is either an
[error code](#errors) of the service, or `ceremony_failed` when the browser or
the user aborted the ceremony (`cause` holds the browser's `DOMException`).

## Cross-origin access

- The JWKS and the helper allow any origin (`Access-Control-Allow-Origin: *`).
- The `/v1/registration/*` and `/v1/authentication/*` routes answer CORS
  requests only from the origins listed in `PA_ORIGINS`: the request `Origin` is
  echoed exactly, with `Vary: Origin`, and credentials are never allowed.
  Preflight requests (`OPTIONS`) are answered for `POST` with `Content-Type`.
  Other origins receive no CORS header, and the browser blocks the response.
- In a same-site deployment these headers are unused. They become useful with
  Related Origin Requests, when another application on a related origin calls
  the service directly; that also needs `/.well-known/webauthn` on the RP ID's
  domain, which is outside this service.

CORS protects nothing on its own: the origin check that matters is the one made
on `clientDataJSON`, which the browser fills in and the authenticator signs.

## Errors

Every error has the same shape:

```json
{ "error": { "code": "verification_failed", "message": "the ceremony could not be verified" } }
```

| Status | `code` | When |
|---|---|---|
| 400 | `invalid_request` | malformed JSON, unknown field, missing or malformed value |
| 400 | `ticket_invalid` | registration ticket unknown, expired or already used |
| 400 | `challenge_invalid` | challenge unknown, expired, already used, or issued for the other ceremony |
| 400 | `credential_unknown` | no such credential for this user handle |
| 400 | `verification_failed` | origin, RP ID, flags, attestation, signature or counter check failed |
| 404 | `not_found` | no such route |
| 405 | `method_not_allowed` | wrong method for the route |
| 413 | `request_too_large` | body over 64 KiB |
| 415 | `unsupported_media_type` | `POST` without `Content-Type: application/json` |
| 500 | `internal` | unexpected error |
| 503 | `unavailable` | too many live challenges: retry later (`Retry-After` is set) |

`message` is for humans and may change. All checks of a ceremony report
`verification_failed` without saying which check failed; the reason is written
to the service log.

Request rates are limited by the reverse proxy (see
[configuration.md](configuration.md#behind-traefik)); the service only caps the
number of live challenges.

## Security properties

The security boundary, the threats and the assurance profiles are described
in [security.md](security.md).

| Property | How |
|---|---|
| Phishing resistance | origin checked against `PA_ORIGINS`, RP ID hash against `PA_RP_ID` |
| No replay | challenges are 32 random bytes, single-use (taken atomically), bound to a ceremony type, valid for `PA_CHALLENGE_TTL` |
| Possession and user verification | `userVerification: "required"`, and the UV flag is checked |
| Cloned authenticators | counter regression rejected |
| No enumeration | discoverable credentials, empty `allowCredentials`, random user handles |
| Forgery towards the host | result token signed with Ed25519, short-lived, audience-bound, nonce-bound |
| Database theft | only public material is stored: credential public keys, counters, flags, user handles, account references and challenges. Registration tickets are stored as SHA-256 hashes, so a stolen database yields no usable ticket. The signing key lives in a mounted file and in memory only. |
