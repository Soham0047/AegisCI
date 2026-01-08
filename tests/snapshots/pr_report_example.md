## 🔐 SecureDev Guardian Report
Base branch: `main`

### Summary
- Total findings: **3**
- By severity: critical=0, high=1, medium=1, low=1, info=0
- By source: tool=1, ml=1, hybrid=1

### Findings by file
#### `src/app.py`
#### [HIGH] B101 — assert_used (lines 10-10)
- Source: `hybrid`
- Confidence: `0.90`
- Location: `src/app.py:10-10`
Evidence:
```python
>> assert True
```
Why:
- Tool: Use of assert detected.
- ML: model=transformer_v3_final risk=0.90 category=injection.sql (conf=0.70) calibrated=yes
- Rationale: Tool finding supported by ML risk score.

#### `src/service.ts`
#### [MEDIUM] injection.xss — injection.xss (lines 5-7)
- Source: `ml_ensemble`
- Confidence: `0.72`
- Location: `src/service.ts:5-7`
Evidence:
```ts
>> element.innerHTML = userInput
```
Why:
- ML: model=ensemble_v1 risk=0.72 category=injection.xss (conf=0.68) calibrated=yes
- Rationale: Model flagged possible XSS pattern.

#### `src/utils.py`
#### [LOW] B321 — hardcoded_tmp (lines 2-2)
- Source: `bandit`
- Confidence: `0.30`
- Location: `src/utils.py:2-2`
Evidence:
```python
>> tempfile = '/tmp/data'
```
Why:
- Tool: Hardcoded temporary directory.
- Rationale: Bandit flagged a risky temp path usage.
