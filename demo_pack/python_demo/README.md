# Python Demo - Automated Vulnerability Patching

This demo shows the SecureDev Guardian pipeline detecting and fixing a command injection vulnerability in Python code.

## Vulnerability

The `app.py` file contains:
```python
subprocess.run(f"ls {user_input}", shell=True)
```

This is vulnerable to command injection (Bandit B602).

## What Happens

1. **Scan**: Bandit detects the `shell=True` vulnerability
2. **Patch**: The orchestrator generates a fix using the deterministic template
3. **Validate**: Docker runs pytest to confirm the fix works
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
```python
def list_files(directory: str) -> str:
    result = subprocess.run(f"ls {directory}", shell=True, capture_output=True, text=True)
    return result.stdout
```

**After (patched):**
```python
def list_files(directory: str) -> str:
    result = subprocess.run(["ls", directory], shell=False, capture_output=True, text=True)
    return result.stdout
```
