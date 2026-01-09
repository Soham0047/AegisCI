import crypto from "crypto";

import { loadPolicy } from "./policy";
import { redactObject } from "./redact";
import type { ArgConstraints, Policy, ToolCallRequest, ToolDecision, ToolPolicy } from "./types";

export function validateToolCall(request: ToolCallRequest, policy?: Policy): ToolDecision {
  const activePolicy = policy ?? loadPolicy();
  const tool = activePolicy.tools.find((item) => item.name === request.tool);
  if (!tool || tool.allowed !== true) {
    return buildDecision(request, "deny", "tool not in allowlist", tool);
  }
  if (!tool.scopes.includes(request.scope)) {
    return buildDecision(request, "deny", "scope not allowed", tool);
  }
  const args = request.args ?? {};
  const violations = validateArgs(args, tool.arg_constraints);
  if (violations.length > 0) {
    return buildDecision(request, "deny", `args schema violation: ${violations[0]}`, tool);
  }

  const { sanitized, findings } = redactObject(args);
  const redactionPatterns = tool.redaction?.patterns;
  const relevantFindings =
    redactionPatterns && redactionPatterns.length > 0
      ? findings.filter((finding) => redactionPatterns.includes(finding.type))
      : findings;
  const hasSecret = relevantFindings.length > 0;
  const redactionMode = tool.redaction?.mode ?? "mask";
  if (hasSecret && redactionMode === "deny") {
    return buildDecision(
      request,
      "deny",
      `secret detected: ${relevantFindings[0].type}`,
      tool,
      sanitized,
    );
  }
  const requiresApproval = tool.requires_approval || request.requires_approval;
  if (requiresApproval && !request.approved) {
    return buildDecision(request, "require_approval", "approval required", tool, sanitized);
  }
  const decision = hasSecret ? "mask" : "allow";
  return buildDecision(request, decision, "allowed", tool, sanitized);
}

function buildDecision(
  request: ToolCallRequest,
  decision: "allow" | "deny" | "mask" | "require_approval",
  reason: string,
  tool?: ToolPolicy,
  sanitizedArgs?: Record<string, unknown>,
): ToolDecision {
  const sanitized = sanitizedArgs ?? request.args;
  const argsHash = hashArgs(sanitized);
  return {
    decision,
    sanitized_args: sanitized as Record<string, unknown>,
    reason,
    policy_rule_id: tool?.name,
    args_hash: argsHash,
    timestamp: new Date().toISOString(),
    correlation_id: request.correlation_id,
  };
}

function validateArgs(args: Record<string, unknown>, constraints?: ArgConstraints): string[] {
  if (!constraints) {
    return [];
  }
  if (constraints.type !== "object") {
    return ["arg_constraints.type must be object"];
  }
  if (constraints.required) {
    for (const key of constraints.required) {
      if (!(key in args)) {
        return [`missing ${key}`];
      }
    }
  }
  const properties = constraints.properties ?? {};
  if (constraints.additionalProperties === false) {
    for (const key of Object.keys(args)) {
      if (!properties[key]) {
        return [`unexpected property ${key}`];
      }
    }
  }
  for (const [key, prop] of Object.entries(properties)) {
    if (!(key in args)) {
      continue;
    }
    const value = args[key];
    if (prop.type && !matchesType(value, prop.type)) {
      return [`${key} type mismatch`];
    }
    if (prop.enum && !prop.enum.includes(value)) {
      return [`${key} not in enum`];
    }
    if (prop.pattern && typeof value === "string") {
      const regex = new RegExp(prop.pattern);
      if (!regex.test(value)) {
        return [`${key} does not match pattern`];
      }
    }
  }
  return [];
}

function matchesType(value: unknown, type: string): boolean {
  if (type === "array") {
    return Array.isArray(value);
  }
  if (type === "object") {
    return typeof value === "object" && value !== null && !Array.isArray(value);
  }
  return typeof value === type;
}

function hashArgs(args: Record<string, unknown>): string {
  const stable = stableStringify(args);
  return crypto.createHash("sha256").update(stable).digest("hex");
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    );
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
