#!/usr/bin/env node
const { spawnSync } = require("child_process");
const net = require("net");

if (process.env.RUN_UI_TESTS !== "1") {
  console.log("RUN_UI_TESTS not set, skipping Playwright.");
  process.exit(0);
}

const HOST = process.env.PLAYWRIGHT_HOST || "127.0.0.1";

const canListen = () =>
  new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.listen(0, HOST, () => {
      server.close(() => resolve(true));
    });
  });

(async () => {
  const ok = await canListen();
  if (!ok) {
    console.log(`Cannot bind to ${HOST}; skipping Playwright.`);
    process.exit(0);
  }
  const result = spawnSync("npx", ["playwright", "test"], {
    stdio: "inherit",
    shell: true,
  });
  process.exit(result.status === null ? 1 : result.status);
})();
