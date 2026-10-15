// Starts one instance of the service, built with -tags e2e, with a fresh
// signing key and database in a temporary directory.
//   node scripts/start-server.mjs <port> <allowed origins>
import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const [port, origins] = process.argv.slice(2);
if (!port || !origins) {
  console.error("usage: start-server.mjs <port> <allowed origins>");
  process.exit(2);
}

const dir = mkdtempSync(join(tmpdir(), `passkey-auth-e2e-${port}-`));
const { privateKey } = generateKeyPairSync("ed25519");
const keyFile = join(dir, "signing-key.pem");
writeFileSync(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });

const binary = process.env.PA_E2E_BINARY ?? resolve(import.meta.dirname, "../../bin/passkey-auth-e2e");
const child = spawn(binary, [], {
  stdio: "inherit",
  env: {
    ...process.env,
    PA_LISTEN: `:${port}`,
    PA_RP_ID: "localhost",
    PA_RP_NAME: "passkey-auth e2e",
    PA_ORIGINS: origins,
    PA_ISSUER: `http://localhost:${port}`,
    PA_AUDIENCE: "e2e-host",
    PA_SIGNING_KEY_FILE: keyFile,
    PA_DB_PATH: join(dir, "passkey-auth.db"),
  },
});
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("exit", (code, signal) => process.exit(code ?? (signal ? 1 : 0)));

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | starts the e2e build with a fresh key and database            |
