# Semgrep and Bandit Rule Reference

## Bandit Rules (Python)

### B101: assert_used
- **Severity**: Low
- **Issue**: Use of assert in production code
- **Risk**: Assertions are disabled with -O flag
- **Fix**: Use proper exception handling instead of assert

### B102: exec_used
- **Severity**: Medium
- **Issue**: Use of exec()
- **Risk**: Code injection
- **Fix**: Avoid exec; use safer alternatives

### B103: set_bad_file_permissions
- **Severity**: Medium
- **Issue**: Setting permissive file permissions (0o777, 0o666)
- **Risk**: Unauthorized file access
- **Fix**: Use restrictive permissions (0o600, 0o644)

### B104: hardcoded_bind_all_interfaces
- **Severity**: Medium
- **Issue**: Binding to 0.0.0.0
- **Risk**: Exposure to network attacks
- **Fix**: Bind to specific interface or localhost

### B105-B107: hardcoded_password
- **Severity**: Medium
- **Issue**: Hardcoded passwords, secrets
- **Risk**: Credential exposure
- **Fix**: Use environment variables or secrets manager

### B108: hardcoded_tmp_directory
- **Severity**: Medium
- **Issue**: Using /tmp directly
- **Risk**: Symlink attacks, race conditions
- **Fix**: Use tempfile module

### B110: try_except_pass
- **Severity**: Low
- **Issue**: try/except with pass
- **Risk**: Silent error suppression
- **Fix**: Log errors or handle appropriately

### B112: try_except_continue
- **Severity**: Low
- **Issue**: try/except with continue in loop
- **Risk**: Silent error suppression
- **Fix**: Log errors before continuing

### B201: flask_debug_true
- **Severity**: High
- **Issue**: Flask debug mode enabled
- **Risk**: Code execution via debugger
- **Fix**: Disable debug in production

### B301-B303: pickle
- **Severity**: Medium
- **Issue**: Use of pickle for deserialization
- **Risk**: Remote code execution
- **Fix**: Use JSON or validate source

### B304-B305: ciphers
- **Severity**: High
- **Issue**: Use of insecure ciphers (DES, Blowfish)
- **Risk**: Weak encryption
- **Fix**: Use AES or ChaCha20

### B306: mktemp_q
- **Severity**: Medium
- **Issue**: Use of tempfile.mktemp()
- **Risk**: Race condition
- **Fix**: Use tempfile.mkstemp() or NamedTemporaryFile

### B307: eval
- **Severity**: Medium
- **Issue**: Use of eval()
- **Risk**: Code injection
- **Fix**: Use ast.literal_eval for literals, avoid otherwise

### B308-B309: mark_safe
- **Severity**: Medium
- **Issue**: Django mark_safe with user input
- **Risk**: XSS
- **Fix**: Sanitize input before marking safe

### B310-B313: URL open
- **Severity**: Medium
- **Issue**: urlopen with user-controlled URL
- **Risk**: SSRF
- **Fix**: Validate URL against allowlist

### B320-B321: XML
- **Severity**: Medium
- **Issue**: Unsafe XML parsing
- **Risk**: XXE attacks
- **Fix**: Use defusedxml

### B323: unverified_context
- **Severity**: High
- **Issue**: SSL context without verification
- **Risk**: Man-in-the-middle attacks
- **Fix**: Enable certificate verification

### B324: hashlib_insecure
- **Severity**: Medium
- **Issue**: Use of MD5/SHA1
- **Risk**: Hash collisions
- **Fix**: Use SHA-256 or better

### B501: request_with_no_cert_validation
- **Severity**: High
- **Issue**: requests with verify=False
- **Risk**: Man-in-the-middle attacks
- **Fix**: Enable certificate verification

### B502-B504: ssl_insecure
- **Severity**: High
- **Issue**: Weak SSL/TLS configuration
- **Risk**: Protocol downgrade attacks
- **Fix**: Use TLS 1.2+ only

### B601-B602: subprocess
- **Severity**: High
- **Issue**: subprocess with shell=True
- **Risk**: Command injection
- **Fix**: Use shell=False with list arguments

### B603-B607: subprocess calls
- **Severity**: Medium
- **Issue**: subprocess with untrusted input
- **Risk**: Command injection
- **Fix**: Validate and sanitize input

### B608: sql_injection
- **Severity**: High
- **Issue**: SQL string formatting
- **Risk**: SQL injection
- **Fix**: Use parameterized queries

### B609: wildcard_injection
- **Severity**: Medium
- **Issue**: Linux wildcard injection
- **Risk**: Command injection via filenames
- **Fix**: Quote arguments, validate filenames

### B610-B611: django_extra
- **Severity**: Medium
- **Issue**: Django extra/RawSQL with user input
- **Risk**: SQL injection
- **Fix**: Use parameterized queries

### B701: jinja2_autoescape_false
- **Severity**: High
- **Issue**: Jinja2 autoescape disabled
- **Risk**: XSS
- **Fix**: Enable autoescape

### B702: mako_templates
- **Severity**: Medium
- **Issue**: Mako template without escaping
- **Risk**: XSS
- **Fix**: Enable default escaping

### B703: django_mark_safe
- **Severity**: Medium
- **Issue**: mark_safe with user input
- **Risk**: XSS
- **Fix**: Sanitize before marking safe

## Semgrep Rules (JavaScript/TypeScript)

### javascript.lang.security.audit.detect-eval
- **Issue**: Use of eval()
- **Risk**: Code injection
- **Fix**: Use JSON.parse for data, avoid eval

### javascript.lang.security.audit.dangerous-exec
- **Issue**: exec() with user input
- **Risk**: Command injection
- **Fix**: Use spawn with array arguments

### javascript.lang.security.audit.sql-injection
- **Issue**: SQL string concatenation
- **Risk**: SQL injection
- **Fix**: Use parameterized queries

### javascript.lang.security.audit.prototype-pollution
- **Issue**: Object merge with untrusted data
- **Risk**: Prototype pollution
- **Fix**: Validate keys, use Object.create(null)

### javascript.browser.security.innerHTML-xss
- **Issue**: innerHTML with user data
- **Risk**: XSS
- **Fix**: Use textContent or sanitization

### javascript.express.security.audit.express-path-traversal
- **Issue**: Path traversal in file operations
- **Risk**: Arbitrary file access
- **Fix**: Validate path within allowed directory

### javascript.jwt.security.audit.jwt-decode-without-verify
- **Issue**: jwt.decode without verification
- **Risk**: Token bypass
- **Fix**: Use jwt.verify with secret

### typescript.react.security.audit.react-dangerouslysetinnerhtml
- **Issue**: dangerouslySetInnerHTML
- **Risk**: XSS
- **Fix**: Sanitize with DOMPurify

### generic.secrets.security.detected-api-key
- **Issue**: Hardcoded API keys
- **Risk**: Credential exposure
- **Fix**: Use environment variables

### generic.secrets.security.detected-private-key
- **Issue**: Private key in code
- **Risk**: Key compromise
- **Fix**: Use secrets manager
