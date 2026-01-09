import { defineConfig } from "@playwright/test";

const HOST = process.env.PLAYWRIGHT_HOST ?? "127.0.0.1";
const PORT = Number(process.env.PLAYWRIGHT_PORT || "3000");

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
