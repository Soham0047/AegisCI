import type { SafeOutputResult } from "./types";
import { redactObject, redactText } from "./redact";

export function classifyOutput(
  output: unknown,
  allowCode: boolean,
  blocklistPatterns: string[] = [],
  origin: "llm" | "tool" = "tool",
): SafeOutputResult {
  const { sanitized, findings } = redactObject(output);
  const text = typeof sanitized === "string" ? sanitized : JSON.stringify(sanitized);
  const containsCode = /```/.test(text);
  const blocked =
    !allowCode && (containsBlocked(text, blocklistPatterns) || containsCode);

  const tags = {
    trusted: origin === "tool" && !blocked,
    untrusted: origin === "llm",
    contains_code: containsCode,
    blocked,
  };

  if (typeof sanitized === "string") {
    const { redacted } = redactText(sanitized);
    return { sanitized_output: redacted, output_tags: tags };
  }
  if (findings.length > 0) {
    return { sanitized_output: sanitized, output_tags: tags };
  }
  return { sanitized_output: sanitized, output_tags: tags };
}

function containsBlocked(text: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern && text.includes(pattern)) {
      return true;
    }
  }
  if (/rm\s+-rf/.test(text)) {
    return true;
  }
  if (/DROP\s+TABLE/i.test(text)) {
    return true;
  }
  if (/curl\s+[^\n]*\|\s*sh/i.test(text)) {
    return true;
  }
  return false;
}
