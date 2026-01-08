import express from "express";
import { loadPolicy } from "./policy";
import { validateToolCall } from "./validator";

const app = express();
app.use(express.json({ limit: "1mb" }));

const policy = loadPolicy();

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/gate", (req, res) => {
  const decision = validateToolCall(req.body, policy);
  return res.json(decision);
});

app.listen(9000, () => {
  console.log("Gateway listening on http://localhost:9000");
});
