// Registration and authentication through the browser helper, for each class
// of authenticator (one Playwright project per class).
import { test, expect, newNonce, ISSUER, AUDIENCE } from "../lib/fixtures.mjs";
import { fetchJWKS, verifyToken } from "../lib/verify.mjs";

const ORIGIN = "http://localhost:8080";

test("registers a passkey, then authenticates with it as a discoverable credential", async ({ webauthn, service, helper, baseURL }, info) => {
  await webauthn.add();
  await helper.open();
  const account = `account-${info.project.name}-${Date.now()}`;
  const jwks = await fetchJWKS(baseURL);
  const synced = !!webauthn.profile.defaultBackupEligibility;

  const reg = await helper.register(await service.ticket(account, "Test user"));
  expect(reg.error).toBeUndefined();
  const r = verifyToken(reg.token, jwks, { issuer: ISSUER, audience: AUDIENCE });
  expect(r).toMatchObject({ ceremony: "registration", sub: account, origin: ORIGIN, uv: true, be: synced, bs: synced });
  expect(r.cred).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(r.exp - r.iat).toBe(60);

  const nonce = newNonce();
  const auth = await helper.authenticate(nonce);
  expect(auth.error).toBeUndefined();
  const a = verifyToken(auth.token, jwks, { issuer: ISSUER, audience: AUDIENCE });
  expect(a).toMatchObject({ ceremony: "authentication", sub: account, origin: ORIGIN, cred: r.cred, nonce, uv: true, be: synced, bs: synced });
  expect(a.jti).not.toBe(r.jti);
});

test("authentication options disclose no credential", async ({ request }) => {
  const res = await request.post("/v1/authentication/options", { data: { nonce: newNonce() } });
  expect(res.status()).toBe(200);
  const { publicKey } = await res.json();
  expect(publicKey.allowCredentials).toEqual([]);
  expect(publicKey.userVerification).toBe("required");
  expect(publicKey.rpId).toBe("localhost");
});

test("a second authenticator can be registered for the same account", async ({ webauthn, service, helper, baseURL }, info) => {
  const first = await webauthn.add();
  await helper.open();
  const account = `account-${info.project.name}-two-${Date.now()}`;
  const jwks = await fetchJWKS(baseURL);
  const check = (t) => verifyToken(t, jwks, { issuer: ISSUER, audience: AUDIENCE });

  const one = check((await helper.register(await service.ticket(account))).token);
  await webauthn.remove(first);
  await webauthn.add();
  const two = check((await helper.register(await service.ticket(account))).token);
  expect(two.sub).toBe(account);
  expect(two.cred).not.toBe(one.cred);

  // The second authenticator logs in to the same account.
  const a = check((await helper.authenticate(newNonce())).token);
  expect(a).toMatchObject({ sub: account, cred: two.cred });
});

test("a bundled copy of the helper works with an explicit baseURL", async ({ page, webauthn, service, helper, baseURL }, info) => {
  await webauthn.add();
  await helper.open();
  const ticket = await service.ticket(`bundled-${info.project.name}-${Date.now()}`);
  // A blob: URL stands for a bundle: the module's own URL says nothing about
  // where the service is.
  const res = await page.evaluate(async ([ticket, base]) => {
    const src = await (await fetch("/v1/passkey-auth.js")).text();
    const m = await import(URL.createObjectURL(new Blob([src], { type: "text/javascript" })));
    try {
      return { token: await m.register(ticket, { baseURL: base }) };
    } catch (e) {
      return { error: e.code ?? String(e) };
    }
  }, [ticket, `${baseURL}/`]);
  expect(res.error).toBeUndefined();
  const claims = verifyToken(res.token, await fetchJWKS(baseURL), { issuer: ISSUER, audience: AUDIENCE });
  expect(claims.ceremony).toBe("registration");
});
