import fs from "fs";
import path from "path";

import { classifyOutput } from "../src/safe_output";
import { loadPolicy, validatePolicy } from "../src/policy";
import { redactObject } from "../src/redact";
import { validateToolCall } from "../src/validator";

function readInput(): any {
  const raw = fs.readFileSync(0, "utf8").trim();
  if (!raw) {
    return {};
  }
  return JSON.parse(raw);
}

function main() {
  const command = process.argv[2];
  const input = readInput();
  if (command === "validate") {
    const policyPath = input.policyPath || process.env.GATEWAY_POLICY_PATH;
    const policy = loadPolicy(policyPath ? path.resolve(policyPath) : undefined);
    const decision = validateToolCall(input.request, policy);
    process.stdout.write(JSON.stringify(decision));
    return;
  }
  if (command === "redact") {
    const result = redactObject(input);
    process.stdout.write(JSON.stringify(result));
    return;
  }
  if (command === "safe-output") {
    const result = classifyOutput(
      input.output,
      Boolean(input.allow_code),
      input.blocklist_patterns || [],
      input.origin || "llm",
    );
    process.stdout.write(JSON.stringify(result));
    return;
  }
  if (command === "validate-policy") {
    const policyPath = input.policyPath || process.env.GATEWAY_POLICY_PATH;
    try {
      const policy = loadPolicy(policyPath ? path.resolve(policyPath) : undefined);
      const errors = validatePolicy(policy);
      if (errors.length > 0) {
        process.stdout.write(JSON.stringify({ ok: false, errors }));
        process.exit(1);
      }
      process.stdout.write(JSON.stringify({ ok: true }));
      return;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "policy invalid";
      process.stdout.write(JSON.stringify({ ok: false, errors: [message] }));
      process.exit(1);
    }
  }
  process.stderr.write("unknown command");
  process.exit(1);
}

main();
