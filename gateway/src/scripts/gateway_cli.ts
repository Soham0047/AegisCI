#!/usr/bin/env node
/**
 * Gateway CLI - Validate tool calls and redact secrets from stdin
 * Usage:
 *   echo '{"tool":"fs.read",...}' | node dist/scripts/gateway_cli.js validate
 *   echo '{"password":"secret"}' | node dist/scripts/gateway_cli.js redact
 */

import { loadPolicy } from "../policy.js";
import { validateToolCall } from "../validator.js";
import { redactObject } from "../redact.js";
import { ToolCallRequest } from "../types.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

async function main(): Promise<void> {
  const command = process.argv[2];

  if (!command || !["validate", "redact"].includes(command)) {
    console.error("Usage: gateway_cli.js <validate|redact>");
    console.error("  validate - Validate a tool call against policy (JSON from stdin)");
    console.error("  redact   - Redact secrets from JSON input (stdin)");
    process.exit(1);
  }

  const input = await readStdin();
  if (!input.trim()) {
    console.error("Error: No input received from stdin");
    process.exit(1);
  }

  try {
    const data = JSON.parse(input);

    if (command === "validate") {
      const policy = loadPolicy();
      const request: ToolCallRequest = {
        tool: data.tool,
        args: data.args || {},
        caller: data.caller || "cli",
        correlation_id: data.correlation_id || `cli-${Date.now()}`,
        scope: data.scope || "read",
      };
      const decision = validateToolCall(request, policy);
      console.log(JSON.stringify(decision, null, 2));
    } else if (command === "redact") {
      const result = redactObject(data);
      console.log(JSON.stringify(result.sanitized, null, 2));
    }
  } catch (err) {
    console.error("Error:", err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

main();
