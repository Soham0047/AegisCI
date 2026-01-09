# Agent Gateway Demo - Policy Enforcement & Audit Logging

This demo shows the SecureDev Guardian gateway validating tool calls from LLM agents against a security policy.

## What It Demonstrates

1. **Allowed Call**: An `fs.read` tool call that matches the policy → ALLOWED
2. **Blocked Call**: A `shell.exec` tool call not in the policy → DENIED
3. **Audit Logging**: All decisions are logged and retrievable via API

## Run

```bash
./run_demo.sh
```

## Expected Output

- `outputs/<timestamp>/allowed_decision.json` - Gateway ALLOW decision
- `outputs/<timestamp>/denied_decision.json` - Gateway DENY decision with reason
- `outputs/<timestamp>/redaction_demo.json` - Secret redaction example
- `outputs/<timestamp>/audit_events.json` - Logged audit events

## Demo Inputs

### Allowed Request (`demo_inputs/allowed_request.json`)
```json
{
  "tool": "fs.read",
  "arguments": {
    "path": "/app/config.json"
  }
}
```

### Blocked Request (`demo_inputs/blocked_request.json`)
```json
{
  "tool": "shell.exec",
  "arguments": {
    "command": "rm -rf /"
  }
}
```

### Redaction Demo (`demo_inputs/secret_input.json`)
```json
{
  "api_key": "ghp_abc123secrettoken",
  "message": "Deploy with Bearer sk-secret-key"
}
```

## Gateway Policy

The gateway uses a YAML policy that defines:
- Which tools are allowed
- Required scopes (read/write)
- Argument constraints (JSON Schema)
- Redaction rules for secrets
- Output blocklist patterns
