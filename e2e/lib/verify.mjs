// Independent verifier of result tokens: Node's built-in crypto and the
// published JWKS, nothing else. This is what a host backend does.
import { createPublicKey, verify } from "node:crypto";

const b64url = (s) => Buffer.from(s, "base64url");

export async function fetchJWKS(baseURL) {
  const res = await fetch(new URL("/.well-known/jwks.json", baseURL));
  if (!res.ok) throw new Error(`JWKS: HTTP ${res.status}`);
  return res.json();
}

/**
 * Verifies a result token and returns its claims; throws on any failure.
 * @param {string} token
 * @param {{keys: object[]}} jwks
 * @param {{issuer: string, audience: string, now?: number}} expected
 */
export function verifyToken(token, jwks, { issuer, audience, now = Date.now() / 1000 }) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("not a compact JWS");
  const [h, p, s] = parts;
  const header = JSON.parse(b64url(h).toString("utf8"));
  if (header.alg !== "EdDSA") throw new Error(`alg ${header.alg}`);
  if (header.typ !== "passkey-result+jwt") throw new Error(`typ ${header.typ}`);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`unknown kid ${header.kid}`);
  const key = createPublicKey({ key: jwk, format: "jwk" });
  if (!verify(null, Buffer.from(`${h}.${p}`), key, b64url(s))) throw new Error("bad signature");
  const claims = JSON.parse(b64url(p).toString("utf8"));
  if (claims.iss !== issuer) throw new Error(`iss ${claims.iss}`);
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(audience)) throw new Error(`aud ${claims.aud}`);
  if (!(claims.exp > now - 5)) throw new Error("expired");
  return claims;
}
