import { defineConfig } from "@playwright/test";

const HOST = process.env.PLAYWRIGHT_HOST ?? "127.0.0.1";
const PORT = Number(process.env.PLAYWRIGHT_PORT || "3001");

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: `http://${HOST}:${PORT}`,
  },
  webServer: {
    command: `rm -rf .next && NEXT_PUBLIC_API_BASE=http://${HOST}:${PORT}/api npm run build && npx next start -p ${PORT}`,
    port: PORT,
    reuseExistingServer: false,
  },
});
