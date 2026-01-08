import fs from "fs";
import path from "path";
import yaml from "js-yaml";

import type { Policy, ToolPolicy } from "./types";

export function loadPolicy(policyPath?: string): Policy {
  const resolved =
    policyPath ?? process.env.GATEWAY_POLICY_PATH ?? path.resolve("policy.yaml");
  const raw = fs.readFileSync(resolved, "utf8");
  const policy = (yaml.load(raw) as Policy) ?? { version: 1, tools: [] };
  const errors = validatePolicy(policy);
  if (errors.length > 0) {
    throw new Error(`policy invalid: ${errors.join("; ")}`);
  }
  return policy;
}

export function validatePolicy(policy: Policy): string[] {
  const errors: string[] = [];
  if (!policy || typeof policy !== "object") {
    return ["policy not an object"];
  }
  if (policy.version !== 1) {
    errors.push("version must be 1");
  }
  if (!Array.isArray(policy.tools)) {
    errors.push("tools must be an array");
    return errors;
  }
  for (const tool of policy.tools) {
    errors.push(...validateTool(tool));
  }
  return errors;
}

function validateTool(tool: ToolPolicy): string[] {
  const errors: string[] = [];
  if (!tool.name) {
    errors.push("tool missing name");
  }
  if (typeof tool.allowed !== "boolean") {
    errors.push(`tool ${tool.name} allowed must be boolean`);
  }
  if (!Array.isArray(tool.scopes) || tool.scopes.length === 0) {
    errors.push(`tool ${tool.name} scopes must be non-empty array`);
  }
  if (tool.arg_constraints) {
    if (tool.arg_constraints.type !== "object") {
      errors.push(`tool ${tool.name} arg_constraints.type must be object`);
    }
  }
  return errors;
}
