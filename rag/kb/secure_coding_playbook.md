# Secure Coding Playbook (Excerpt)

## JavaScript DOM sinks
Avoid assigning untrusted input to `innerHTML`. Prefer `textContent` for
plain text.

## Python subprocess safety
Avoid `shell=True` unless you are executing a trusted string. If the command
is already a list or tuple, remove `shell=True` or set `shell=False`.

## Constant-time comparisons
Use `hmac.compare_digest(a, b)` when comparing secrets or signatures to avoid
timing side channels.
