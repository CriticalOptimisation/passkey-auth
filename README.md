# passkey-auth
Passwordless authentication with WebAuthn passkeys, shipped as a container image pinned by digest

The service proves that the person in front of a browser holds the passkey
bound to an account of the host application, and returns a short-lived signed
result token. It keeps no session and stores public key material only.

- [API contract](docs/api.md): routes, browser helper, result token, errors
- [Configuration](docs/configuration.md): environment variables, signing key, storage
