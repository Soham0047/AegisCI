# Approved Fix Patterns

## Python Security Fixes

### subprocess.run shell=True with list args
- Pattern: `subprocess.run([..], shell=True)`
- Fix: remove `shell=True` when the command is a list/tuple.
- Example:
  ```python
  # Bad
  subprocess.run(["ls", "-la"], shell=True)
  # Good
  subprocess.run(["ls", "-la"], shell=False)
  ```

### Constant-time secret comparison
- Pattern: `token_a == token_b` for secrets
- Fix: `hmac.compare_digest(token_a, token_b)` and add `import hmac`.
- Example:
  ```python
  # Bad
  if user_token == stored_token:
  # Good
  import hmac
  if hmac.compare_digest(user_token, stored_token):
  ```

### SQL Injection Prevention
- Pattern: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
- Fix: Use parameterized queries with placeholders.
- Example:
  ```python
  # Bad
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  # Good
  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  ```

### Hardcoded Secrets
- Pattern: `password = "secret123"` or `API_KEY = "sk-xxx"`
- Fix: Use environment variables or secrets manager.
- Example:
  ```python
  # Bad
  API_KEY = "sk-live-abc123"
  # Good
  import os
  API_KEY = os.environ.get("API_KEY")
  ```

### Insecure Random for Security
- Pattern: `random.randint()` for tokens/passwords
- Fix: Use `secrets` module for cryptographic randomness.
- Example:
  ```python
  # Bad
  import random
  token = random.randint(0, 999999)
  # Good
  import secrets
  token = secrets.token_hex(16)
  ```

### Path Traversal Prevention
- Pattern: `open(user_provided_path)` without validation
- Fix: Validate path is within allowed directory.
- Example:
  ```python
  # Bad
  with open(user_path) as f:
  # Good
  from pathlib import Path
  safe_path = Path(base_dir).joinpath(user_path).resolve()
  if not safe_path.is_relative_to(base_dir):
      raise ValueError("Invalid path")
  ```

### Pickle Deserialization
- Pattern: `pickle.load(untrusted_data)`
- Fix: Use JSON or validate source; avoid pickle for untrusted data.
- Example:
  ```python
  # Bad
  data = pickle.load(request.body)
  # Good
  data = json.loads(request.body)
  ```

### XML External Entity (XXE)
- Pattern: `xml.etree.ElementTree.parse(untrusted_xml)`
- Fix: Use defusedxml library.
- Example:
  ```python
  # Bad
  import xml.etree.ElementTree as ET
  tree = ET.parse(user_xml)
  # Good
  import defusedxml.ElementTree as ET
  tree = ET.parse(user_xml)
  ```

### Eval/Exec Injection
- Pattern: `eval(user_input)` or `exec(user_input)`
- Fix: Never use eval/exec with user input; use ast.literal_eval for literals.
- Example:
  ```python
  # Bad
  result = eval(user_expression)
  # Good
  import ast
  result = ast.literal_eval(user_expression)  # Only for literals
  ```

### YAML Safe Loading
- Pattern: `yaml.load(data)` without Loader
- Fix: Use `yaml.safe_load()` to prevent code execution.
- Example:
  ```python
  # Bad
  data = yaml.load(file_content)
  # Good
  data = yaml.safe_load(file_content)
  ```

## JavaScript/TypeScript Security Fixes

### innerHTML assignment
- Pattern: `element.innerHTML = userInput`
- Fix: `element.textContent = userInput` for plain text.
- Example:
  ```javascript
  // Bad
  element.innerHTML = userMessage;
  // Good
  element.textContent = userMessage;
  ```

### RegExp from untrusted input
- Pattern: `new RegExp(userInput)`
- Fix: `new RegExp(escapeRegExp(userInput))` with local helper.
- Example:
  ```javascript
  // Bad
  const regex = new RegExp(userInput);
  // Good
  const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(escapeRegExp(userInput));
  ```

### eval() Usage
- Pattern: `eval(userInput)`
- Fix: Never use eval; use JSON.parse for data or safer alternatives.
- Example:
  ```javascript
  // Bad
  const config = eval(userConfig);
  // Good
  const config = JSON.parse(userConfig);
  ```

### Prototype Pollution
- Pattern: `Object.assign(target, untrustedObject)`
- Fix: Validate keys, block __proto__ and constructor.
- Example:
  ```javascript
  // Bad
  Object.assign(config, userInput);
  // Good
  const safeAssign = (target, source) => {
    for (const key of Object.keys(source)) {
      if (key === '__proto__' || key === 'constructor') continue;
      target[key] = source[key];
    }
  };
  ```

### SQL Injection (Node.js)
- Pattern: String concatenation in SQL queries
- Fix: Use parameterized queries.
- Example:
  ```javascript
  // Bad
  db.query(`SELECT * FROM users WHERE id = ${userId}`);
  // Good
  db.query('SELECT * FROM users WHERE id = ?', [userId]);
  ```

### Path Traversal (Node.js)
- Pattern: `fs.readFile(userPath)`
- Fix: Validate path is within allowed directory.
- Example:
  ```javascript
  // Bad
  fs.readFile(path.join(baseDir, userPath));
  // Good
  const resolved = path.resolve(baseDir, userPath);
  if (!resolved.startsWith(path.resolve(baseDir))) {
    throw new Error('Invalid path');
  }
  ```

### Command Injection
- Pattern: `exec(userInput)` or `spawn` with shell
- Fix: Use spawn with array arguments, no shell.
- Example:
  ```javascript
  // Bad
  exec(`ls ${userDir}`);
  // Good
  spawn('ls', [userDir], { shell: false });
  ```

### JWT Verification
- Pattern: `jwt.decode(token)` without verification
- Fix: Always use `jwt.verify()` with secret.
- Example:
  ```javascript
  // Bad
  const payload = jwt.decode(token);
  // Good
  const payload = jwt.verify(token, process.env.JWT_SECRET);
  ```

### CORS Misconfiguration
- Pattern: `Access-Control-Allow-Origin: *` with credentials
- Fix: Specify allowed origins explicitly.
- Example:
  ```javascript
  // Bad
  res.header('Access-Control-Allow-Origin', '*');
  // Good
  const allowedOrigins = ['https://example.com'];
  if (allowedOrigins.includes(req.headers.origin)) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
  }
  ```

## General Security Patterns

### Password Hashing
- Pattern: Plain text passwords or weak hashing (MD5, SHA1)
- Fix: Use bcrypt, argon2, or scrypt.
- Python:
  ```python
  # Bad
  hashed = hashlib.md5(password.encode()).hexdigest()
  # Good
  import bcrypt
  hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
  ```

### HTTPS Enforcement
- Pattern: HTTP URLs for sensitive operations
- Fix: Always use HTTPS for API calls and redirects.

### Input Validation
- Pattern: Missing input validation
- Fix: Validate type, length, format, and range of all inputs.

### Error Message Leakage
- Pattern: Exposing stack traces or internal errors to users
- Fix: Log detailed errors server-side; return generic messages to users.
