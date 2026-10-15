// What a browser-driven attacker or a faulty client can observe. Forged RP ID
// hashes and counter regressions cannot be produced through a browser; the Go
// tests cover them with a software authenticator.
import { test, expect, newNonce, ISSUER, AUDIENCE } from "../lib/fixtures.mjs";
import { fetchJWKS, verifyToken } from "../lib/verify.mjs";

test("a replayed authentication response is rejected", async ({ page, webauthn, service, helper, request }, info) => {
  await webauthn.add();
  await helper.open();
  expect((await helper.register(await service.ticket(`replay-${info.project.name}-${Date.now()}`))).token).toBeTruthy();

  const captured = page.waitForRequest((r) => r.url().endsWith("/v1/authentication/verify"));
  expect((await helper.authenticate(newNonce())).token).toBeTruthy();
  const body = (await captured).postData();

  const replay = await request.post("/v1/authentication/verify", { headers: { "Content-Type": "application/json" }, data: body });
  expect(replay.status()).toBe(400);
  expect((await replay.json()).error.code).toBe("challenge_invalid");
});

test("a tampered result token fails verification", async ({ webauthn, service, helper, baseURL }, info) => {
  await webauthn.add();
  await helper.open();
  const { token } = await helper.register(await service.ticket(`tamper-${info.project.name}-${Date.now()}`));
  const jwks = await fetchJWKS(baseURL);
  const opts = { issuer: ISSUER, audience: AUDIENCE };
  expect(() => verifyToken(token, jwks, opts)).not.toThrow();

  const [h, p, s] = token.split(".");
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  claims.sub = "someone-else";
  const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
  expect(() => verifyToken(forged, jwks, opts)).toThrow(/bad signature/);
});

test("a ceremony on an origin outside the allow-list is rejected", async ({ webauthn, service, helper }, info) => {
  // The "other" instance only accepts https://elsewhere.example; the page runs
  // on its own origin, http://localhost:8081.
  const other = "http://localhost:8081";
  await webauthn.add();
  await helper.open(other);
  const res = await helper.register(await service.ticket(`origin-${info.project.name}-${Date.now()}`, "Origin", other));
  expect(res).toEqual({ error: "verification_failed" });
});

test("an authenticator that cannot verify the user cannot register", async ({ webauthn, service, helper }, info) => {
  await webauthn.add({ isUserVerified: false });
  await helper.open();
  const res = await helper.register(await service.ticket(`no-uv-${info.project.name}-${Date.now()}`));
  expect(res.token).toBeUndefined();
  expect(["ceremony_failed", "verification_failed"]).toContain(res.error);
});

test("the helper is served to any origin", async ({ request }) => {
  const res = await request.get("/v1/passkey-auth.js", { headers: { Origin: "https://third-party.example" } });
  expect(res.status()).toBe(200);
  expect(res.headers()["access-control-allow-origin"]).toBe("*");
  expect(res.headers()["content-type"]).toMatch(/^text\/javascript/);
});

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | replay, tampering, origin, missing UV                         |
