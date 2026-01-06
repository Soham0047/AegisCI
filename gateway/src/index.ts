import express from "express";
import fs from "fs";
import yaml from "js-yaml";

type Policy = {
  tools?: { allowlist?: string[] };
  safety?: { require_human_approval_for?: string[] };
  secrets?: { block_patterns?: string[] };
};

function loadPolicy(): Policy {
  const raw = fs.readFileSync(new URL("../policy.yaml", import.meta.url), "utf8");
  return (yaml.load(raw) as Policy) ?? {};
}

const app = express();
app.use(express.json({ limit: "1mb" }));

const policy = loadPolicy();

app.get("/health", (_req, res) => res.json({ ok: true }));

// Baseline "tool-call gate" endpoint. Later we'll add auditing, tainting, and strict schema checks.
app.post("/gate", (req, res) => {
  const { tool, args } = req.body ?? {};
  const allowlist = policy.tools?.allowlist ?? [];
  if (!tool || typeof tool !== "string") {
    return res.status(400).json({ allowed: false, reason: "missing tool" });
  }
  if (allowlist.length > 0 && !allowlist.includes(tool)) {
    return res.status(403).json({ allowed: false, reason: `tool not allowlisted: ${tool}` });
  }
  return res.json({ allowed: true });
});

app.listen(9000, () => {
  console.log("Gateway listening on http://localhost:9000");
});
