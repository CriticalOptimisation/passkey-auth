// The host application of the e2e tests: a P-256 key, its DID document, and
// host tokens signed with Node's built-in crypto (docs/api.md, Host
// authentication). start-server.mjs creates one host per service instance and
// writes it to a file in the system's temporary directory, where the fixtures
// read it.
import { createHash, createPrivateKey, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// The e2e build reads the document from a file: the DID need not resolve.
export const HOST_DID = "did:web:e2e-host.localhost";

// The host listener of the instance on `port`.
export const HOST_PORT_OFFSET = 1000;
export const hostPort = (port) => Number(port) + HOST_PORT_OFFSET;

// Lifetime of a host token, in seconds: the most docs/api.md allows.
export const HOST_TOKEN_SECONDS = 60;

const hostFile = (port) => join(tmpdir(), `passkey-auth-e2e-host-${port}.json`);
const b64 = (v) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

/** Creates the host of the instance on `port`, and returns its DID document. */
export function createHost(port) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { crv, kty, x, y } = publicKey.export({ format: "jwk" });
  // RFC 7638 thumbprint: the required members, in lexicographic order.
  const fragment = createHash("sha256").update(JSON.stringify({ crv, kty, x, y })).digest("base64url");
  const kid = `${HOST_DID}#${fragment}`;
  writeFileSync(hostFile(port), JSON.stringify({ kid, privateJwk: privateKey.export({ format: "jwk" }) }), { mode: 0o600 });
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
    id: HOST_DID,
    verificationMethod: [{ id: kid, type: "JsonWebKey", controller: HOST_DID, publicKeyJwk: { crv, kty, x, y } }],
    authentication: [kid],
  };
}

/** A host token for the instance on `port`, whose PA_ISSUER is `audience`. */
export function hostToken(port, audience) {
  const { kid, privateJwk } = JSON.parse(readFileSync(hostFile(port), "utf8"));
  const iat = Math.floor(Date.now() / 1000);
  const input = `${b64({ alg: "ES256", typ: "passkey-host+jwt", kid })}.${b64({ iss: HOST_DID, aud: audience, iat, exp: iat + HOST_TOKEN_SECONDS })}`;
  const key = createPrivateKey({ key: privateJwk, format: "jwk" });
  return `${input}.${sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}
