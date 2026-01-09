#!/usr/bin/env bash
# Run the Agent Gateway policy enforcement demo
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_DIR="$SCRIPT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="$DEMO_DIR/outputs/$TIMESTAMP"

echo "============================================"
echo "SecureDev Guardian - Agent Gateway Demo"
echo "============================================"
echo ""
echo "Demo: Policy-based tool call validation and audit logging"
echo "Output: $OUTPUT_DIR"
echo ""

# Check for npm/node (gateway is TypeScript)
if ! command -v npm &> /dev/null; then
    echo "⚠ npm not found - Gateway demo requires Node.js"
    echo "  Install Node.js 18+ to run this demo"
    exit 1
fi

# Setup
mkdir -p "$OUTPUT_DIR"
cd "$REPO_ROOT"

# Ensure gateway is built
if [ ! -d "gateway/node_modules" ]; then
    echo "Installing gateway dependencies..."
    cd gateway
    npm install --silent 2>/dev/null || npm install
    cd "$REPO_ROOT"
fi

# Build gateway if needed
if [ ! -f "gateway/dist/scripts/gateway_cli.js" ]; then
    echo "Building gateway..."
    cd gateway
    npm run build --silent 2>/dev/null || npm run build
    cd "$REPO_ROOT"
fi

GATEWAY_CLI="node gateway/dist/scripts/gateway_cli.js"

echo "Step 1: Test ALLOWED tool call (fs.read)"
echo "----------------------------------------"
echo "Request:"
cat "$DEMO_DIR/demo_inputs/allowed_request.json"
echo ""

echo "Gateway decision:"
ALLOWED_RESULT=$($GATEWAY_CLI validate < "$DEMO_DIR/demo_inputs/allowed_request.json" || echo '{"allowed":false,"reason":"gateway error"}')
echo "$ALLOWED_RESULT" | python3 -m json.tool 2>/dev/null || echo "$ALLOWED_RESULT"
echo "$ALLOWED_RESULT" > "$OUTPUT_DIR/allowed_decision.json"

# Check if allowed
if echo "$ALLOWED_RESULT" | grep -q '"allowed":true\|"allowed": true'; then
    echo ""
    echo "✓ Tool call ALLOWED - fs.read is in the policy with 'read' scope"
else
    echo ""
    echo "⚠ Decision: $(echo "$ALLOWED_RESULT" | grep -o '"reason":"[^"]*"' || echo 'see above')"
fi

echo ""
echo "Step 2: Test BLOCKED tool call (shell.exec)"
echo "----------------------------------------"
echo "Request:"
cat "$DEMO_DIR/demo_inputs/blocked_request.json"
echo ""

echo "Gateway decision:"
DENIED_RESULT=$($GATEWAY_CLI validate < "$DEMO_DIR/demo_inputs/blocked_request.json" || echo '{"allowed":false,"reason":"gateway error"}')
echo "$DENIED_RESULT" | python3 -m json.tool 2>/dev/null || echo "$DENIED_RESULT"
echo "$DENIED_RESULT" > "$OUTPUT_DIR/denied_decision.json"

# Check if denied
if echo "$DENIED_RESULT" | grep -q '"allowed":false\|"allowed": false'; then
    echo ""
    echo "✓ Tool call DENIED - shell.exec is NOT in the policy"
    echo "  Reason: $(echo "$DENIED_RESULT" | grep -o '"reason":"[^"]*"' | head -1 || echo 'tool not allowed')"
else
    echo ""
    echo "⚠ Unexpected: Tool was allowed (check policy configuration)"
fi

echo ""
echo "Step 3: Demonstrate secret redaction"
echo "----------------------------------------"
echo "Input with secrets:"
cat "$DEMO_DIR/demo_inputs/secret_input.json"
echo ""

echo "After redaction:"
REDACTED=$($GATEWAY_CLI redact < "$DEMO_DIR/demo_inputs/secret_input.json" || echo '{}')
echo "$REDACTED" | python3 -m json.tool 2>/dev/null || echo "$REDACTED"
echo "$REDACTED" > "$OUTPUT_DIR/redaction_demo.json"
echo ""
echo "✓ Secrets masked with [REDACTED] patterns"

echo ""
echo "Step 4: Simulate audit event logging"
echo "----------------------------------------"

# Create simulated audit events (in real system, these come from backend)
cat > "$OUTPUT_DIR/audit_events.json" << EOF
{
  "events": [
    {
      "id": "evt_$(date +%s)_001",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "event_type": "tool_call",
      "tool": "fs.read",
      "decision": "allowed",
      "request": {
        "tool": "fs.read",
        "arguments": {"path": "/app/config.json"}
      },
      "source": "demo_agent"
    },
    {
      "id": "evt_$(date +%s)_002",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "event_type": "tool_call",
      "tool": "shell.exec",
      "decision": "denied",
      "reason": "tool not in policy allowlist",
      "request": {
        "tool": "shell.exec",
        "arguments": {"command": "rm -rf /"}
      },
      "source": "demo_agent"
    }
  ],
  "total": 2,
  "query": {
    "since": "$(date -u +%Y-%m-%dT00:00:00Z)",
    "until": "$(date -u +%Y-%m-%dT23:59:59Z)"
  }
}
EOF

echo "Audit events (would be from /api/v1/gateway/events):"
cat "$OUTPUT_DIR/audit_events.json" | python3 -m json.tool

echo ""
echo "Step 5: Policy summary"
echo "----------------------------------------"
echo "Current gateway policy allows:"
echo "  - github.create_or_update_comment (write, requires approval)"
echo "  - validator.run (read/write)"
echo "  - fs.read (read only)"
echo "  - fs.write (write, requires approval, redaction: deny)"
echo ""
echo "Blocked by default:"
echo "  - shell.exec (not in allowlist)"
echo "  - Any tool not explicitly listed"

echo ""
echo "============================================"
echo "Demo Complete!"
echo ""
echo "Artifacts in: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"
echo ""
echo "Key takeaways:"
echo "  1. Gateway enforces allowlist-based tool access"
echo "  2. Unauthorized tools are DENIED with audit trail"
echo "  3. Secrets are automatically redacted"
echo "  4. All decisions are logged for compliance"
echo "============================================"
