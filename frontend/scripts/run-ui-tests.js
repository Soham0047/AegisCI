#!/usr/bin/env node
const { spawnSync } = require("child_process");

if (process.env.RUN_UI_TESTS !== "1") {
  console.log("RUN_UI_TESTS not set, skipping Playwright.");
  process.exit(0);
}

const result = spawnSync("npx", ["playwright", "test"], {
  stdio: "inherit",
  shell: true,
});
process.exit(result.status === null ? 1 : result.status);
