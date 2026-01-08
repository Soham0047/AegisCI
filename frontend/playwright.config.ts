import { defineConfig } from "@playwright/test";

const PORT = 3000;
const HOST = "127.0.0.1";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: `http://${HOST}:${PORT}`,
  },
  webServer: {
    command: `NEXT_PUBLIC_API_BASE=http://${HOST}:${PORT}/api npm run dev -- --hostname ${HOST} --port ${PORT}`,
    port: PORT,
    reuseExistingServer: !process.env.CI,
  },
});
