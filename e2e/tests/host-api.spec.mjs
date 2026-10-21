// The host-facing API, driven as the host backend would: with host tokens, on
// the host listener only.
import { test, expect } from "../lib/fixtures.mjs";

test("a revoked passkey can no longer log in", async ({ webauthn, service, helper }, info) => {
  await webauthn.add();
  await helper.open();
  const account = `revoke-${info.project.name}-${Date.now()}`;
  expect((await helper.register(await service.ticket(account))).token).toBeTruthy();

  const [cred] = await service.credentials(account);
  expect(cred.id).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(await service.revoke(account, cred.id)).toBe(204);
  expect(await service.credentials(account)).toEqual([]);

  // The authenticator still holds the passkey; the service no longer knows it.
  expect(await helper.authenticate(Buffer.alloc(32, 1).toString("base64url"))).toEqual({ error: "credential_unknown" });
});

test("the public listener does not serve the host routes", async ({ request, service }) => {
  const headers = { Authorization: `Bearer ${service.token()}` };
  const res = await request.post("/v1/registration-tickets", { headers, data: { account: "a", displayName: "A" } });
  expect(res.status()).toBe(404);
  expect((await res.json()).error.code).toBe("not_found");
  expect((await request.get("/v1/accounts/a/credentials", { headers })).status()).toBe(404);
});

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #14    | revoked passkey; host routes absent from the public port      |
