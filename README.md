# passkey-auth
Passwordless authentication with WebAuthn passkeys, shipped as a container image pinned by digest

The service proves that the person in front of a browser holds the passkey
bound to an account of the host application, and returns a short-lived signed
result token. It keeps no session and stores public key material only.

- [API contract](docs/api.md): routes, browser helper, result token, errors
- [Configuration](docs/configuration.md): environment variables, signing key, storage, Traefik
- [Security model](docs/security.md): security boundary, threats, assurance profiles (any passkey, attested hardware key)

## Personal data (GDPR)

This section describes, for the controller's data protection assessment, what
the service processes. It is a technical description, not legal advice.

**What is stored, and for how long.** Everything is pseudonymous: the service
never receives a name, an e-mail address or a document. It does receive the
display name of a registration ticket, which it deletes with the ticket.

| Data | Kept | Personal data? |
|---|---|---|
| account reference (an opaque identifier chosen by the host) | until the host revokes the account's credentials | yes, pseudonymous: the host can link it to a person |
| user handle (64 random bytes) | same | yes, pseudonymous |
| per credential: credential ID, public key, algorithm, authenticator model (AAGUID), flags, signature counter, creation and last-use times | until revoked by the host | yes, pseudonymous: it describes a person's device and when it was used |
| registration ticket: account reference, display name, ticket hash | until used, at most `PA_TICKET_TTL` (15 min) | yes; the display name may be a real name |
| challenge, with its account reference or host nonce | until used, at most `PA_CHALLENGE_TTL` (5 min) | yes, briefly |
| service logs | per the operator's log retention | the service logs no IP address and no account reference; the helper usage log records the origin of a website, not a person |

**What is never processed.**
- **Biometric data.** A fingerprint or face check happens inside the
  authenticator, and the service only receives a yes/no "user verified" flag.
  No special-category data (Art. 9) is processed.
- Passwords, and anything secret of the user. The service holds public keys
  only.
- Cookies or tracking identifiers, so no consent banner is needed for the
  service.

**Roles.**
- The host application is the **controller** of its accounts and of their
  authentication.
- Operated by the host's own organisation, the service is part of that
  processing.
- Operated for another organisation, its operator is a **processor**, and a
  processing agreement (Art. 28) is needed.

**Declarations.** The GDPR has no prior declaration or authorisation (in
France, CNIL declarations ended in May 2018). Authenticating identified users
is processing of personal data, so the following obligations remain, but they
belong to the controller and are light:

- an entry "authentication by passkey" in the record of processing activities
  (Art. 30);
- a mention in the host's privacy notice (Art. 13). The usual legal basis is
  the performance of the contract with the user (Art. 6(1)(b));
- deletion when an account is closed: the host revokes the account's
  credentials through the host-facing API (#5);
- an impact assessment (Art. 35) is not triggered by this service. The host's
  overall processing may trigger one, for example large-scale age
  verification or minors' data;
- breach handling: a stolen database yields no usable secret, which lowers the
  risk to assess (Art. 33–34), but it is still a breach of pseudonymous data.

**Keeping the footprint minimal.**
- Hosts should pass an opaque account reference, never an e-mail address.
- Hosts should pass a display name the user recognises without it being their
  legal name, for example "Library card 1234". Password managers show it to
  the user.
- Passkeys synced by a platform (Google, Apple) are stored by that provider
  under the user's own agreement with it. That storage is not processing by
  the host or by this service.

<!--
Change History

| PR  | Summary |
|-----|---------|
| #12 | pointers to the docs; personal data (GDPR) section |
-->
