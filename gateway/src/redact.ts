import type { SecretFinding } from "./types";

const KEY_REGEX = /token|secret|apikey|api_key|authorization/i;
const VALUE_PATTERNS: Array<{ type: string; regex: RegExp }> = [
  { type: "github_token", regex: /ghp_[A-Za-z0-9]{36}/ },
  { type: "github_token", regex: /github_pat_[A-Za-z0-9_]{20,}/ },
  { type: "openai_key", regex: /sk-[A-Za-z0-9]{20,}/ },
  { type: "generic_bearer", regex: /Bearer\s+[A-Za-z0-9._-]+/ },
  { type: "jwt", regex: /[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/ },
];

function maskValue(value: string): string {
  if (value.length <= 8) {
    return "***REDACTED***";
  }
  const prefix = value.slice(0, 4);
  const suffix = value.slice(-4);
  return `${prefix}***${suffix}`;
}

export function redactText(text: string): { redacted: string; findings: SecretFinding[] } {
  let redacted = text;
  const findings: SecretFinding[] = [];
  for (const pattern of VALUE_PATTERNS) {
    redacted = redacted.replace(pattern.regex, (match) => {
      findings.push({ path: "<text>", type: pattern.type, masked: maskValue(match) });
      return maskValue(match);
    });
  }
  return { redacted, findings };
}

export function redactObject(obj: unknown): { sanitized: unknown; findings: SecretFinding[] } {
  const findings: SecretFinding[] = [];
  const sanitized = redactValue(obj, "", findings);
  return { sanitized, findings };
}

function redactValue(value: unknown, path: string, findings: SecretFinding[]): unknown {
  if (typeof value === "string") {
    for (const pattern of VALUE_PATTERNS) {
      if (pattern.regex.test(value)) {
        findings.push({ path, type: pattern.type, masked: maskValue(value) });
        return maskValue(value);
      }
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => redactValue(item, `${path}[${index}]`, findings));
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      const keyPath = path ? `${path}.${key}` : key;
      if (KEY_REGEX.test(key) && typeof val === "string") {
        const match = VALUE_PATTERNS.find((pattern) => pattern.regex.test(val));
        findings.push({
          path: keyPath,
          type: match ? match.type : "key_match",
          masked: maskValue(val),
        });
        result[key] = maskValue(val);
        continue;
      }
      result[key] = redactValue(val, keyPath, findings);
    }
    return result;
  }
  return value;
}
