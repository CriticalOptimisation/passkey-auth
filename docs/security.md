# Security model

This document states what a result token proves, which components are
trusted to make that proof hold, and how to deploy the service where the
user's browser can be trusted and where it cannot.

- [What the service proves](#what-the-service-proves)
- [Components and the security boundary](#components-and-the-security-boundary)
- [What each check relies on](#what-each-check-relies-on)
- [Threats and residual risks](#threats-and-residual-risks)
- [Deployment profiles](#deployment-profiles)
- [Obligations of the host](#obligations-of-the-host)
- [Out of scope](#out-of-scope)

## What the service proves

A result token states, under the service's signature:

> Within the last `PA_TOKEN_TTL` seconds, on a page of origin `origin`, an
> authenticator holding the private key of credential `cred` signed a
> challenge issued by this service, after verifying its user (`uv`). That
> credential was registered for account `sub`, with a registration ticket
> that the host issued.

It does **not** state:

- **who the person is.** The host established that when it issued the
  registration ticket;
- **that the person meant to perform this ceremony.** This depends on the
  browser (see [the browser's role](#the-browser));
- **that the authenticator is a hardware device**, unless the deployment
  requires attestation (see [Profile C](#profile-c-untrusted-browser-attested-hardware-keys)).

## Components and the security boundary

```
             trusted for its stated role          not trusted
  ┌──────────────────────────────────────────┐
  │ authenticator   browser + OS (profile-   │   network (TLS protects it)
  │                 dependent, see below)    │   page scripts and the helper
  │ passkey-auth    signing key   config     │   any caller of the public routes
  │ Traefik (TLS)   host backend             │   other containers on the network
  └──────────────────────────────────────────┘   database content (integrity: see below)
```

### Trusted components

| Component | Trusted for | Why this trust is reasonable |
|---|---|---|
| **Authenticator** | keeping the private key secret; signing only after user presence (UP) and, when asked, user verification (UV); reporting its counter and backup flags honestly | The private key never leaves it. A hardware key enforces this in a secure element; a platform authenticator enforces it in the OS's protected key store. The flags are inside the signed authenticator data, so nobody downstream can alter them. |
| **Browser and OS** | writing the true page origin into `clientDataJSON`, using the RP ID the page is entitled to, and showing the user a real ceremony | This is the WebAuthn trust model: the browser is the only party that sees the page's origin. How far this trust holds is what separates the [deployment profiles](#deployment-profiles). |
| **passkey-auth** (code, configuration, clock) | checking every ceremony and signing only verified results | It is the relying party. Its configuration (`PA_RP_ID`, `PA_ORIGINS`) sets what the checks compare against. |
| **Result-signing key** | proving that a token comes from the service | Whoever holds it can forge a token for any account. It lives only in a mounted file and in memory. |
| **Traefik** | TLS termination; rate limits | It is the only path from the LAN or the Internet to the service. |
| **Host backend** | issuing registration tickets to the right person; verifying tokens; deciding what a login grants | The host owns the accounts. Every registration starts from its decision. |

### Untrusted components

| Component | Why it is not trusted | What protects against it |
|---|---|---|
| **The network** | it can be observed or modified | TLS through Traefik for anything leaving the machine. The WebAuthn challenge and signatures make captured traffic useless for replay. |
| **Page scripts, including the browser helper** | they run in the page and may be modified, bundled, or replaced | Nothing the helper does is trusted: the service verifies the authenticator's signed data and the origin the browser wrote. A *malicious script running on an allowed origin* is a different matter: see [XSS](#threats-and-residual-risks). |
| **Callers of the public routes** | anyone on the Internet may call them | Registration needs a ticket. Verification needs a valid signature on a live, single-use challenge. Rate limits apply to every route. |
| **Other containers on the shared network** | they can reach the service without going through Traefik | Host-facing routes authenticate every request in the service itself (#5). Public routes need no caller identity. |
| **Database, for confidentiality** | a copy may leak | It holds only public material: public keys, pseudonymous identifiers, hashed tickets. A leaked copy forges nothing. |
| **Database, for integrity** | **this one matters** | An attacker who can *write* to it can add their own public key under any account, then log in as that account. Protect write access like the signing key: a volume reachable only by the service, no shared database user, backups as sensitive as the key. |

### The browser

WebAuthn trusts the browser to tell the truth about the page. The browser
writes `clientDataJSON` (origin, challenge, type), chooses the RP ID it asks
the authenticator to use, and decides what the user sees. The authenticator
signs whatever the browser hands it.

- **An honest browser** never lets a page on another origin obtain a
  signature for this RP ID. Phishing then fails, because a look-alike site
  cannot produce a valid ceremony.
- **A compromised browser**, or malware controlling it, can:
  - put any origin and any challenge into `clientDataJSON`. It can therefore
    relay a live ceremony from an attacker's session to the user's
    authenticator, which turns a single touch of the user into an attacker's
    login;
  - capture a PIN that travels through it (CTAP clientPIN);
  - **without attestation, play the authenticator itself**: create credentials
    in software and set UV, with nobody present. Nothing in a passkey without
    attestation tells a software authenticator from a real device.
- **What it cannot do**, against an attested hardware key, is extract the key,
  emulate the device, or produce a signature without a physical touch.

Hence the deployment profiles below.

## What each check relies on

| Check (in the service) | Defeats | Relies on |
|---|---|---|
| origin in `clientDataJSON` ∈ `PA_ORIGINS`, byte for byte | phishing on look-alike sites | honest browser |
| RP ID hash = `PA_RP_ID` | credentials of another site | authenticator; honest browser |
| challenge known, unexpired, unused, of the right ceremony | replay, pre-computed responses | service storage |
| UP and UV flags | stolen authenticator used without PIN or biometric | authenticator |
| signature with the registered public key | everything else | authenticator's private key |
| counter strictly increasing (when not 0) | cloned authenticator | authenticator; meaningful for hardware keys only, since synced passkeys report 0 |
| registration ticket, single use | registering a passkey for someone else's account | host issues it only to the right person, over its own authenticated channel |
| attestation chain and AAGUID allow-list (#9) | software or uncertified authenticators | manufacturer's attestation key and the FIDO Metadata Service |
| token signature, `aud`, `exp`, `nonce` (host side) | forged or replayed results | secrecy of the signing key; the host's checks |

## Threats and residual risks

| Threat | Outcome | Mitigation |
|---|---|---|
| Phishing site | fails: wrong origin, so the browser refuses and the service rejects | none needed with an honest browser |
| **XSS on an allowed origin** | an injected script can run a ceremony *as the page*: the user sees a genuine prompt, and the token is valid | the host's own XSS defences (CSP, output encoding). The host's nonce, bound to its server-side login attempt, means the token is only accepted for the session that asked for it. |
| Stolen authenticator | useless without PIN or biometric (UV) | UV required; the host revokes the credential (#5) |
| Unlocked device left with an open session | outside WebAuthn | the host's session policy |
| Malware or a compromised browser | see [The browser](#the-browser) | profile C limits it to "one touch, one ceremony"; nothing can stop a compromised browser from misdirecting a touch the user gives |
| Stolen registration ticket | the thief registers their own passkey on the account | short TTL, single use, delivered over the host's authenticated session; the host can list and revoke credentials (#5) |
| Leaked database | nothing forgeable | public material only |
| **Database write access** | attacker adds a credential, takes over accounts | access control on the volume and backups |
| **Signing key theft** | forged tokens for any account | file permissions, secret mount; rotation (`PA_PREVIOUS_SIGNING_KEY_FILE`) |
| Denial of service | ceremonies refused | Traefik rate limits per IP and global; challenge cap |
| Lost all authenticators | user locked out | recovery by the host (#8); users are encouraged to register two authenticators |

## Deployment profiles

The service's checks are the same in every profile. What changes is what the
deployment can rely on from the browser, and therefore what it must require
from the authenticator.

### Profile A: consumer web (default)

The ordinary web: users' own devices and browsers, synced passkeys accepted.

- **Assumption:** browsers are honest, as everywhere on the web.
- **Settings:** the defaults of #4. UV required, attestation recorded but not
  required.
- **What it gives:** phishing resistance and no shared secret. This is far
  stronger than passwords or one-time codes, but the device itself is not
  vouched for.

### Profile B: trusted browser (managed corporate environment)

Devices and browsers under the organisation's control.

- **Conditions under which the browser can be trusted:**
  - browser versions centrally managed and kept up to date by policy;
  - extensions allow-listed;
  - devices managed (MDM) with endpoint protection;
  - Internet access filtered, which cuts the main routes for malware and
    phishing.
- **Settings:**
  - the defaults of #4 apply;
  - authenticators may be the platform's (for example Windows Hello) or keys
    issued by the organisation;
  - **optional, enterprise attestation.** The browser policy names the RP IDs
    allowed to receive individual attestation, and the service can then tell
    *which* issued key was used. This needs the attestation policy of #9;
  - **optional, refuse synced passkeys**, if credentials must not leave
    managed devices. The host rejects tokens with `be: true`, or #9 refuses
    them at registration.
- **What it gives:** profile A's guarantees, plus confidence that ceremonies
  happen on managed devices. The trust in the browser comes from the
  organisation's management, not from WebAuthn.

### Profile C: untrusted browser, attested hardware keys

Browsers that cannot be vouched for: unmanaged devices, high-value
operations, or users who may be under attack.

- **Requirements** (the attestation policy of #9; not yet implemented in #4,
  which records `fmt` and `aaguid` only):
  - `attestation: "direct"`. Registration **refuses** `none` and self
    attestation;
  - the attestation chain is verified against the FIDO Metadata Service
    (MDS3). The device's status must not be revoked or compromised;
  - **AAGUID allow-list** limited to hardware keys of the required
    certification level;
  - **`be` must be false**: hardware keys are not backup-eligible, so their
    credential cannot be copied;
  - UV required. Prefer keys that verify the user **on the key** (built-in
    biometric): their PIN never goes through the browser.
- **What it gives:**
  - the credential lives in certified hardware and cannot be copied, so the
    counter check becomes meaningful;
  - every ceremony needs a physical touch of that key;
  - a compromised browser cannot register a software authenticator, and
    cannot log in without the key.
- **What it does not give:** a compromised browser can still spend a genuine
  touch on a ceremony other than the one the user thinks they are doing, for
  example a relayed login. The guarantee is "this key and a human touch", not
  "this intention". Where intention matters (approving a payment, for
  example), the host must confirm the operation over another channel.

### Choosing

| Question | A | B | C |
|---|---|---|---|
| Who controls the browser? | the user | the organisation | nobody we trust |
| Synced passkeys | yes | optional | no |
| Attestation required | no | optional (enterprise) | yes, hardware only |
| A software authenticator in a compromised browser can register | yes | prevented by management | no |
| Available in #4 | yes | yes, except the attestation options (#9) | no: needs #9 |

## Obligations of the host

1. Issue a registration ticket only to the person the account belongs to, over
   the host's own authenticated channel. Every guarantee rests on this step.
2. Verify every token as `docs/api.md` describes: signature with the JWKS,
   `typ`, `iss`, `aud`, `exp`, `ceremony`; for an authentication, a `nonce`
   that it issued for this login attempt and that has not been used before;
   and `origin` when several applications share a deployment.
3. Apply its profile's policy to `be`/`bs` (and, from #9, `aaguid`).
4. Protect its own pages against XSS, since a script on an allowed origin can
   run ceremonies.
5. Revoke credentials when an authenticator is lost and when an account is
   closed (#5).

## Out of scope

- Identity proofing at enrolment and account recovery: the host's
  responsibility (#8).
- Sessions after login: the host's responsibility.
- Compromise of the host backend: it can issue tickets and accept tokens at
  will.
- Physical coercion of the user.
