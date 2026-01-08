# Gold Labeling Guide

## Purpose
Gold labels provide a high-quality evaluation set to measure precision, reduce false positives,
and calibrate the weak-label pipeline.

## Verdicts
- **TP**: The finding is a real security issue in the code snippet.
- **FP**: The finding is not a real security issue for this context.
- **UNCERTAIN**: Ambiguous or needs more context than provided.

## Category (Controlled Vocabulary)
Use one of these values:
- injection.command
- injection.sql
- injection.xss
- crypto.insecure
- auth.session
- secrets.exposure
- deserialization.unsafe
- path.traversal
- ssrf
- unsafe.exec
- dependency.vuln
- misc.other

## Fix Type (Controlled Vocabulary)
Use one of these values:
- sanitize_input
- use_safe_api
- parameterize_query
- escape_output
- remove_eval_exec
- validate_path
- rotate_secret
- upgrade_dependency
- add_auth_check
- add_tests
- no_fix_needed
- unknown

## Examples
1) **Bandit (Python)**
   - Finding: `B101` "Use of assert detected" in production code.
   - Verdict: FP if only used in tests; TP if in prod path.
   - Category: misc.other
   - Fix type: no_fix_needed or add_tests

2) **Semgrep (JS/TS)**
   - Finding: `ts.no-eval` on `eval(userInput)`.
   - Verdict: TP
   - Category: injection.command
   - Fix type: remove_eval_exec

3) **Ambiguous**
   - Finding: weak severity crypto warning in test helper.
   - Verdict: UNCERTAIN
   - Category: crypto.insecure
   - Fix type: unknown

## Notes
Add brief notes when:
- Context is missing
- You suspect a false positive but are not fully sure
- The fix might be non-obvious

## Overlap (Inter-annotator Agreement)
Some items are duplicated across annotators to measure agreement. Use the same rules
as above and label independently.
