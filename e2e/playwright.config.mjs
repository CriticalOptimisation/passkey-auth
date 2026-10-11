// Both classes of authenticator run the same suite, each as a project.
// Two service instances: "main" accepts the test page's origin, "other"
// accepts only a different one, to check origin enforcement.
import { defineConfig } from "@playwright/test";

const MAIN = 8080;
const OTHER = 8081;

export default defineConfig({
  testDir: "./tests",
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://localhost:${MAIN}`,
    browserName: "chromium",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "roaming", use: { authenticator: "roaming" } },
    { name: "platform", use: { authenticator: "platform" } },
  ],
  webServer: [
    {
      command: `node scripts/start-server.mjs ${MAIN} http://localhost:${MAIN}`,
      url: `http://localhost:${MAIN}/.well-known/jwks.json`,
      reuseExistingServer: false,
      stdout: "pipe",
    },
    {
      command: `node scripts/start-server.mjs ${OTHER} https://elsewhere.example`,
      url: `http://localhost:${OTHER}/.well-known/jwks.json`,
      reuseExistingServer: false,
      stdout: "pipe",
    },
  ],
});
