## 🔐 SecureDev Guardian Report
Base branch: `main`

### Summary
- Total findings: **9**
- By severity: critical=0, high=0, medium=0, low=9, info=0
- By source: tool=9, ml=0, hybrid=0

### Findings by file
#### `guardian/git_utils.py`
#### [LOW] B404 — B404 (lines 1-1)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/git_utils.py:1-1`
Evidence:
```python
>> import subprocess


```
Why:
- Tool: Consider possible security implications associated with the subprocess module.
- Rationale: Bandit reported B404 at line 1.

#### [LOW] B603 — B603 (lines 6-6)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/git_utils.py:6-6`
Evidence:
```python
   def _run(cmd: list[str], check: bool = True) -> str:
       try:
>>         return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()
       except subprocess.CalledProcessError:
           if check:
```
Why:
- Tool: subprocess call - check for execution of untrusted input.
- Rationale: Bandit reported B603 at line 6.

#### `guardian/report.py`
#### [LOW] B404 — B404 (lines 4-4)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/report.py:4-4`
Evidence:
```python

   import json
>> import subprocess
   from dataclasses import dataclass
   from datetime import datetime, timezone
```
Why:
- Tool: Consider possible security implications associated with the subprocess module.
- Rationale: Bandit reported B404 at line 4.

#### [LOW] B603 — B603 (lines 59-59)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/report.py:59-59`
Evidence:
```python
   def _get_git_sha() -> str:
       try:
>>         return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
       except Exception:
           return "unknown"
```
Why:
- Tool: subprocess call - check for execution of untrusted input.
- Rationale: Bandit reported B603 at line 59.

#### [LOW] B607 — B607 (lines 59-59)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/report.py:59-59`
Evidence:
```python
   def _get_git_sha() -> str:
       try:
>>         return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
       except Exception:
           return "unknown"
```
Why:
- Tool: Starting a process with a partial executable path
- Rationale: Bandit reported B607 at line 59.

#### `guardian/scanners/bandit_scanner.py`
#### [LOW] B404 — B404 (lines 2-2)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/scanners/bandit_scanner.py:2-2`
Evidence:
```python
   import json
>> import subprocess
   from typing import Any

```
Why:
- Tool: Consider possible security implications associated with the subprocess module.
- Rationale: Bandit reported B404 at line 2.

#### [LOW] B603 — B603 (lines 13-13)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/scanners/bandit_scanner.py:13-13`
Evidence:
```python
       cmd = ["bandit", "-f", "json", "-q", *py_files]
       try:
>>         out = subprocess.check_output(cmd, text=True)
           return json.loads(out)
       except FileNotFoundError:
```
Why:
- Tool: subprocess call - check for execution of untrusted input.
- Rationale: Bandit reported B603 at line 13.

#### `guardian/scanners/semgrep_scanner.py`
#### [LOW] B404 — B404 (lines 2-2)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/scanners/semgrep_scanner.py:2-2`
Evidence:
```python
   import json
>> import subprocess
   from typing import Any

```
Why:
- Tool: Consider possible security implications associated with the subprocess module.
- Rationale: Bandit reported B404 at line 2.

#### [LOW] B603 — B603 (lines 13-13)
- Source: `bandit`
- Confidence: `0.90`
- Location: `guardian/scanners/semgrep_scanner.py:13-13`
Evidence:
```python
       cmd = ["semgrep", "--config", config, "--json", *files]
       try:
>>         out = subprocess.check_output(cmd, text=True)
           return json.loads(out)
       except FileNotFoundError:
```
Why:
- Tool: subprocess call - check for execution of untrusted input.
- Rationale: Bandit reported B603 at line 13.
