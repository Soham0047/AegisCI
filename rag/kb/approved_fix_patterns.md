# Approved Fix Patterns

## Python: subprocess.run shell=True with list args
- Pattern: `subprocess.run([..], shell=True)`
- Fix: remove `shell=True` when the command is a list/tuple.

## Python: constant-time secret comparison
- Pattern: `token_a == token_b` for secrets
- Fix: `hmac.compare_digest(token_a, token_b)` and add `import hmac`.

## JS/TS: innerHTML assignment
- Pattern: `element.innerHTML = userInput`
- Fix: `element.textContent = userInput` for plain text.

## JS/TS: RegExp from untrusted input
- Pattern: `new RegExp(userInput)`
- Fix: `new RegExp(escapeRegExp(userInput))` with local helper.
