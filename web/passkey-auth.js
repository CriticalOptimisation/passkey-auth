// passkey-auth browser helper. Contract: docs/api.md, "Browser helper".
// It holds no secret and is not part of the security boundary.

export const version = "1";

/** Rejection of register() and authenticate(): `code` is a service error
 * code, or "ceremony_failed" when the browser or the user aborted. */
export class PasskeyAuthError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "PasskeyAuthError";
    this.code = code;
  }
}

/** Registers a passkey with a ticket from the host backend; resolves to the
 * result token. Options: baseURL, signal. */
export async function register(ticket, options = {}) {
  const base = serviceRoot(options);
  const { publicKey } = await post(base, "v1/registration/options", { ticket });
  const credential = await ceremony(() =>
    navigator.credentials.create({ publicKey: creationOptions(publicKey), signal: options.signal }),
  );
  const { token } = await post(base, "v1/registration/verify", credentialJSON(credential));
  return token;
}

/** Authenticates with a nonce from the host backend; resolves to the result
 * token. Options: baseURL, signal, conditional (passkey autofill). */
export async function authenticate(nonce, options = {}) {
  const base = serviceRoot(options);
  const { publicKey } = await post(base, "v1/authentication/options", { nonce });
  const request = { publicKey: requestOptions(publicKey), signal: options.signal };
  if (options.conditional) request.mediation = "conditional";
  const credential = await ceremony(() => navigator.credentials.get(request));
  const { token } = await post(base, "v1/authentication/verify", credentialJSON(credential));
  return token;
}

// The service root: options.baseURL, else the root next to this module when
// it is loaded from the service. A bundled copy must pass baseURL.
function serviceRoot(options) {
  if (options.baseURL) {
    const u = new URL(options.baseURL, globalThis.location?.href);
    return u.href.endsWith("/") ? u.href : `${u.href}/`;
  }
  try {
    const u = new URL("..", import.meta.url);
    if (u.protocol === "https:" || u.protocol === "http:") return u.href;
  } catch {
    // import.meta.url is not hierarchical (blob:, data:): fall through.
  }
  throw new PasskeyAuthError("invalid_request", "baseURL is required when the helper is not loaded from the service");
}

async function post(base, path, body) {
  let res;
  try {
    res = await fetch(new URL(path, base), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      credentials: "omit",
    });
  } catch (e) {
    throw new PasskeyAuthError("ceremony_failed", `network error: ${e.message}`, { cause: e });
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new PasskeyAuthError(data?.error?.code ?? "internal", data?.error?.message ?? `HTTP ${res.status}`);
  }
  return data;
}

async function ceremony(run) {
  let credential;
  try {
    credential = await run();
  } catch (e) {
    throw new PasskeyAuthError("ceremony_failed", e.message, { cause: e });
  }
  if (!credential) throw new PasskeyAuthError("ceremony_failed", "no credential returned");
  return credential;
}

const fromB64 = (s) => {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
};
const toB64 = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const descriptors = (list = []) => list.map((d) => ({ ...d, id: fromB64(d.id) }));

function creationOptions(o) {
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(o);
  return { ...o, challenge: fromB64(o.challenge), user: { ...o.user, id: fromB64(o.user.id) }, excludeCredentials: descriptors(o.excludeCredentials) };
}

function requestOptions(o) {
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(o);
  return { ...o, challenge: fromB64(o.challenge), allowCredentials: descriptors(o.allowCredentials) };
}

function credentialJSON(c) {
  if (typeof c.toJSON === "function") return c.toJSON();
  const r = c.response;
  const response = { clientDataJSON: toB64(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = toB64(r.attestationObject);
    response.transports = r.getTransports?.() ?? [];
  } else {
    response.authenticatorData = toB64(r.authenticatorData);
    response.signature = toB64(r.signature);
    if (r.userHandle) response.userHandle = toB64(r.userHandle);
  }
  return {
    id: c.id,
    rawId: toB64(c.rawId),
    type: c.type,
    response,
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
    clientExtensionResults: c.getClientExtensionResults(),
  };
}
