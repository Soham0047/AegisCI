# TypeScript Demo - Automated Vulnerability Patching

This demo shows the SecureDev Guardian pipeline detecting and fixing XSS and unsafe eval vulnerabilities in TypeScript code.

## Vulnerabilities

The `src/app.ts` file contains:
1. `element.innerHTML = userInput` - XSS vulnerability
2. `eval(jsonString)` - Code injection via eval

## What Happens

1. **Scan**: ESLint/Semgrep detect the vulnerabilities
2. **Patch**: The orchestrator generates fixes using deterministic templates
3. **Validate**: npm test runs ESLint + TypeScript + Jest
4. **Select**: The ranker picks the best validated patch
5. **Output**: A PR comment markdown is generated

## Run

```bash
./run_demo.sh
```

## Expected Output

- `outputs/<timestamp>/selected.diff` - The selected patch
- `outputs/<timestamp>/validation_report.json` - Validation results
- `outputs/<timestamp>/pr_comment.md` - Ready-to-post PR comment
- `outputs/<timestamp>/tests_output.txt` - Test execution output

## Before/After

**Before (vulnerable):**
```typescript
function renderMessage(element: HTMLElement, message: string): void {
  element.innerHTML = message;  // XSS!
}

function parseConfig(jsonString: string): unknown {
  return eval(jsonString);  // Code injection!
}
```

**After (patched):**
```typescript
function renderMessage(element: HTMLElement, message: string): void {
  element.textContent = message;  // Safe
}

function parseConfig(jsonString: string): unknown {
  return JSON.parse(jsonString);  // Safe
}
```
