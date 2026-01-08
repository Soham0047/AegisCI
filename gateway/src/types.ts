export type ToolCallRequest = {
  tool: string;
  args: Record<string, unknown>;
  caller: string;
  correlation_id: string;
  scope: string;
  requires_approval?: boolean;
  approved?: boolean;
};

export type ToolPolicy = {
  name: string;
  allowed: boolean;
  scopes: string[];
  requires_approval?: boolean;
  arg_constraints?: ArgConstraints;
  redaction?: {
    mode: "mask" | "deny";
    patterns?: string[];
  };
  output?: {
    allow_code: boolean;
    blocklist_patterns?: string[];
  };
};

export type Policy = {
  version: number;
  tools: ToolPolicy[];
};

export type ArgConstraints = {
  type: "object";
  properties?: Record<
    string,
    {
      type: "string" | "number" | "boolean" | "array" | "object";
      pattern?: string;
      enum?: unknown[];
    }
  >;
  required?: string[];
  additionalProperties?: boolean;
};

export type ToolDecision = {
  decision: "allow" | "deny" | "mask" | "require_approval";
  sanitized_args: Record<string, unknown>;
  reason: string;
  policy_rule_id?: string;
  args_hash: string;
  timestamp: string;
  correlation_id: string;
};

export type SecretFinding = {
  path: string;
  type: string;
  masked: string;
};

export type SafeOutputResult = {
  sanitized_output: unknown;
  output_tags: {
    trusted: boolean;
    untrusted: boolean;
    contains_code?: boolean;
    blocked?: boolean;
  };
};
