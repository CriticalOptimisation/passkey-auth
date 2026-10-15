// Fixtures: a CDP virtual authenticator of the project's class, the service's
// test routes, and the browser helper driven from the test page.
import { test as base, expect } from "@playwright/test";

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

  /** Test-only routes of the e2e build. */
  service: async ({ request, baseURL }, use) => {
    await use({
      async ticket(account, displayName = account, url = baseURL) {
        const res = await request.post(new URL("/test/tickets", url).href, { data: { account, displayName } });
        expect(res.status()).toBe(200);
        return (await res.json()).ticket;
      },
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

export const newNonce = () => Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | virtual authenticators, test routes, helper driver            |
