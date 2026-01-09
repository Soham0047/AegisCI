# Security Code Examples

## Python Secure Coding Examples

### Secure Password Hashing

```python
# INSECURE - Never do this
import hashlib
def hash_password_bad(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# SECURE - Use bcrypt
import bcrypt
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)
```

### Secure Token Generation

```python
# INSECURE - Predictable tokens
import random
def generate_token_bad() -> str:
    return str(random.randint(100000, 999999))

# SECURE - Cryptographically secure
import secrets
def generate_token() -> str:
    return secrets.token_urlsafe(32)

def generate_api_key() -> str:
    return f"sk_{secrets.token_hex(24)}"
```

### Secure File Operations

```python
# INSECURE - Path traversal vulnerability
def read_file_bad(user_path: str) -> str:
    with open(f"/data/{user_path}") as f:
        return f.read()

# SECURE - Validate path
from pathlib import Path

def read_file_secure(user_path: str, base_dir: str = "/data") -> str:
    base = Path(base_dir).resolve()
    requested = (base / user_path).resolve()

    if not requested.is_relative_to(base):
        raise ValueError("Access denied: path traversal attempt")

    if not requested.is_file():
        raise FileNotFoundError("File not found")

    return requested.read_text()
```

### Secure SQL Queries

```python
# INSECURE - SQL injection
def get_user_bad(conn, user_id: str):
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchone()

# SECURE - Parameterized query
def get_user(conn, user_id: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

# SECURE - SQLAlchemy ORM
from sqlalchemy.orm import Session
from models import User

def get_user_orm(db: Session, user_id: int) -> User | None:
    return db.query(User).filter(User.id == user_id).first()
```

### Secure Subprocess Execution

```python
# INSECURE - Command injection
import subprocess

def run_command_bad(user_input: str) -> str:
    result = subprocess.run(f"ls {user_input}", shell=True, capture_output=True)
    return result.stdout.decode()

# SECURE - No shell, list arguments
def run_command(directory: str) -> str:
    # Validate input
    allowed_dirs = ["/home", "/var/log"]
    if not any(directory.startswith(d) for d in allowed_dirs):
        raise ValueError("Invalid directory")

    result = subprocess.run(
        ["ls", "-la", directory],
        shell=False,
        capture_output=True,
        text=True
    )
    return result.stdout
```

### Secure HTTP Requests

```python
# INSECURE - No SSL verification
import requests

def fetch_url_bad(url: str):
    return requests.get(url, verify=False)

# SECURE - With validation and timeouts
def fetch_url(url: str, timeout: int = 10):
    # Validate URL
    from urllib.parse import urlparse
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid URL scheme")

    # Block internal IPs (SSRF prevention)
    import socket
    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ip.startswith(("10.", "172.", "192.168.", "127.")):
            raise ValueError("Internal URLs not allowed")
    except socket.gaierror:
        raise ValueError("Could not resolve hostname")

    return requests.get(url, verify=True, timeout=timeout)
```

### Secure YAML Loading

```python
# INSECURE - Arbitrary code execution
import yaml

def load_config_bad(config_file: str):
    with open(config_file) as f:
        return yaml.load(f)  # Dangerous!

# SECURE - Safe loading
def load_config(config_file: str):
    with open(config_file) as f:
        return yaml.safe_load(f)
```

## JavaScript/TypeScript Secure Coding Examples

### Secure DOM Manipulation

```javascript
// INSECURE - XSS vulnerability
function displayMessage_bad(userMessage) {
    document.getElementById('output').innerHTML = userMessage;
}

// SECURE - Text content
function displayMessage(userMessage) {
    document.getElementById('output').textContent = userMessage;
}

// SECURE - If HTML needed, sanitize
import DOMPurify from 'dompurify';

function displayHtml(userHtml) {
    const clean = DOMPurify.sanitize(userHtml);
    document.getElementById('output').innerHTML = clean;
}
```

### Secure SQL Queries (Node.js)

```javascript
// INSECURE - SQL injection
async function getUserBad(pool, userId) {
    const result = await pool.query(
        `SELECT * FROM users WHERE id = '${userId}'`
    );
    return result.rows[0];
}

// SECURE - Parameterized query
async function getUser(pool, userId) {
    const result = await pool.query(
        'SELECT * FROM users WHERE id = $1',
        [userId]
    );
    return result.rows[0];
}
```

### Secure JWT Handling

```javascript
// INSECURE - No signature verification
const jwt = require('jsonwebtoken');

function getUserFromToken_bad(token) {
    return jwt.decode(token);  // Does NOT verify!
}

// SECURE - Verify signature
function getUserFromToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
            issuer: 'my-app'
        });
    } catch (error) {
        throw new Error('Invalid token');
    }
}
```

### Secure Object Merging

```javascript
// INSECURE - Prototype pollution
function mergeConfig_bad(defaults, userConfig) {
    return { ...defaults, ...userConfig };
}

// SECURE - Filter dangerous keys
function mergeConfig(defaults, userConfig) {
    const BLOCKED_KEYS = ['__proto__', 'constructor', 'prototype'];

    const safeConfig = {};
    for (const [key, value] of Object.entries(userConfig)) {
        if (!BLOCKED_KEYS.includes(key)) {
            safeConfig[key] = value;
        }
    }

    return { ...defaults, ...safeConfig };
}
```

### Secure Path Handling (Node.js)

```javascript
const path = require('path');
const fs = require('fs').promises;

// INSECURE - Path traversal
async function readFileBad(userPath) {
    return fs.readFile(path.join('/data', userPath), 'utf8');
}

// SECURE - Validate path
async function readFile(userPath, baseDir = '/data') {
    const resolved = path.resolve(baseDir, userPath);
    const base = path.resolve(baseDir);

    if (!resolved.startsWith(base + path.sep)) {
        throw new Error('Access denied: path traversal attempt');
    }

    return fs.readFile(resolved, 'utf8');
}
```

### Secure Command Execution

```javascript
const { spawn } = require('child_process');

// INSECURE - Command injection
function runCommand_bad(userInput) {
    const { exec } = require('child_process');
    exec(`ls ${userInput}`, (err, stdout) => {
        console.log(stdout);
    });
}

// SECURE - Spawn with array arguments
function runCommand(directory) {
    return new Promise((resolve, reject) => {
        const proc = spawn('ls', ['-la', directory], {
            shell: false,
            timeout: 5000
        });

        let output = '';
        proc.stdout.on('data', data => output += data);
        proc.on('close', code => {
            if (code === 0) resolve(output);
            else reject(new Error(`Exit code: ${code}`));
        });
    });
}
```

### Secure Cookie Settings

```javascript
// Express.js secure session cookies
app.use(session({
    name: 'sessionId',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,      // Prevent XSS access
        secure: true,        // HTTPS only
        sameSite: 'strict',  // CSRF protection
        maxAge: 3600000      // 1 hour
    }
}));
```

### Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

// Apply to login endpoint
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: 'Too many login attempts, please try again later'
});

app.post('/login', loginLimiter, loginHandler);
```
