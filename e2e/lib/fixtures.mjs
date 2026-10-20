// Fixtures: a CDP virtual authenticator of the project's class, the host-facing
// API of the service, and the browser helper driven from the test page.
import { test as base, expect } from "@playwright/test";
import { hostPort, hostToken } from "./host.mjs";

export const PROFILES = {
  // Roaming CTAP2 USB security key with resident keys and user verification.
  roaming: {
    protocol: "ctap2",
    transport: "usb",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
  // Platform authenticator holding a synced passkey.
  platform: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
    defaultBackupEligibility: true,
    defaultBackupState: true,
  },
};

export const ISSUER = "http://localhost:8080";
export const AUDIENCE = "e2e-host";

export const test = base.extend({
  authenticator: ["roaming", { option: true }],

  /** Adds and removes virtual authenticators on the page. */
  webauthn: async ({ page, authenticator }, use) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const add = async (overrides = {}) =>
      (await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: { ...PROFILES[authenticator], ...overrides },
      })).authenticatorId;
    const remove = (authenticatorId) => cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    await use({ add, remove, profile: PROFILES[authenticator] });
  },

  /** The host-facing API of the instance at `url`, called as its host. */
  service: async ({ request, baseURL }, use) => {
    const host = (url, method, path, data) => {
      const { port, origin } = new URL(url);
      return request.fetch(`http://localhost:${hostPort(port)}${path}`, {
        method,
        data,
        headers: { Authorization: `Bearer ${hostToken(port, origin)}` },
      });
    };
    const credentialsPath = (account) => `/v1/accounts/${encodeURIComponent(account)}/credentials`;
    await use({
      async ticket(account, displayName = account, url = baseURL) {
        const res = await host(url, "POST", "/v1/registration-tickets", { account, displayName });
        expect(res.status()).toBe(201);
        return (await res.json()).ticket;
      },
      async credentials(account, url = baseURL) {
        const res = await host(url, "GET", credentialsPath(account));
        expect(res.status()).toBe(200);
        return res.json();
      },
      async revoke(account, id, url = baseURL) {
        return (await host(url, "DELETE", `${credentialsPath(account)}/${id}`)).status();
      },
      token: (url = baseURL) => hostToken(new URL(url).port, new URL(url).origin),
    });
  },

  /** Runs the browser helper on the test page of the given service. */
  helper: async ({ page, baseURL }, use) => {
    const call = (fn, arg) =>
      page.evaluate(
        async ([fn, arg]) => {
          const m = await import("/v1/passkey-auth.js");
          try {
            return { token: await m[fn](...arg) };
          } catch (e) {
            return { error: e instanceof m.PasskeyAuthError ? e.code : `not a PasskeyAuthError: ${e}` };
          }
        },
        [fn, arg],
      );
    await use({
      open: (url = baseURL) => page.goto(new URL("/test/", url).href),
      register: (ticket) => call("register", [ticket]),
      authenticate: (nonce) => call("authenticate", [nonce]),
    });
  },
});

export { expect };

// Random bytes of a host nonce: within the 16 to 64 of docs/api.md.
export const NONCE_BYTES = 32;

export const newNonce = () => Buffer.from(crypto.getRandomValues(new Uint8Array(NONCE_BYTES))).toString("base64url");

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | virtual authenticators, test routes, helper driver            |
// | #14    | tickets, list and revoke through the host API                 |
