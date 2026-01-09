# Secure Coding Playbook

## Python Security Best Practices

### Subprocess Safety
Avoid `shell=True` unless you are executing a trusted string. If the command
is already a list or tuple, remove `shell=True` or set `shell=False`.

When you must use shell=True:
- Never interpolate user input directly
- Use shlex.quote() to escape arguments
- Prefer subprocess.run() over os.system()

### Constant-time Comparisons
Use `hmac.compare_digest(a, b)` when comparing secrets or signatures to avoid
timing side channels. Regular string comparison (`==`) can leak information
about how many characters match through timing differences.

### SQL Injection Prevention
Always use parameterized queries instead of string formatting:
- SQLAlchemy: Use bound parameters
- sqlite3: Use ? placeholders
- psycopg2: Use %s with tuple

### Input Validation
- Validate all user inputs on the server side
- Use allowlists over blocklists when possible
- Sanitize file paths to prevent directory traversal
- Limit input lengths to prevent DoS attacks

### Authentication & Sessions
- Use strong password hashing (bcrypt, argon2)
- Implement rate limiting on login endpoints
- Use secure session cookies (HttpOnly, Secure, SameSite)
- Implement proper logout that invalidates sessions

### Secrets Management
- Never hardcode API keys, passwords, or tokens
- Use environment variables or dedicated secrets managers
- Rotate secrets regularly
- Don't log sensitive information

### File Upload Security
- Validate file types by content, not just extension
- Store uploads outside web root
- Generate random filenames
- Scan for malware if possible

### Error Handling
- Never expose stack traces to end users
- Log detailed errors server-side
- Return generic error messages to clients
- Use structured error codes for API responses

## JavaScript/TypeScript Security Best Practices

### DOM XSS Prevention
Avoid assigning untrusted input to `innerHTML`. Prefer `textContent` for
plain text. If HTML is needed, use a sanitization library like DOMPurify.

Dangerous sinks to avoid:
- element.innerHTML
- element.outerHTML
- document.write()
- eval()
- setTimeout/setInterval with strings

### Prototype Pollution
Freeze prototypes when possible and validate object keys:
- Block `__proto__`, `constructor`, `prototype` keys
- Use Object.create(null) for dictionaries
- Consider using Map instead of plain objects

### Regular Expression DoS (ReDoS)
Avoid catastrophic backtracking in regex:
- Limit input length before regex matching
- Avoid nested quantifiers like (a+)+
- Use atomic groups or possessive quantifiers when available
- Consider using RE2 for untrusted patterns

### Third-party Dependencies
- Regularly audit dependencies (npm audit)
- Use lockfiles (package-lock.json)
- Consider using Snyk or similar tools
- Minimize dependency count

### API Security
- Validate all input on the server
- Use CORS properly (specific origins, not *)
- Implement rate limiting
- Use HTTPS for all endpoints
- Validate JWTs properly (signature, expiry, issuer)

### Content Security Policy
Implement CSP headers to prevent XSS:
- Avoid 'unsafe-inline' and 'unsafe-eval'
- Use nonces or hashes for inline scripts
- Specify allowed sources for scripts, styles, images

## OWASP Top 10 Quick Reference

### A01: Broken Access Control
- Implement proper authorization checks
- Use deny-by-default access control
- Validate user permissions on every request
- Log access control failures

### A02: Cryptographic Failures
- Use strong encryption (AES-256, RSA-2048+)
- Protect data in transit (TLS 1.2+)
- Hash passwords with bcrypt/argon2
- Don't use deprecated algorithms (MD5, SHA1, DES)

### A03: Injection
- Use parameterized queries
- Validate and sanitize input
- Escape output appropriate to context
- Use ORMs when possible

### A04: Insecure Design
- Use threat modeling
- Implement defense in depth
- Follow secure design patterns
- Limit resource consumption

### A05: Security Misconfiguration
- Remove default credentials
- Disable unnecessary features
- Keep software updated
- Use security headers

### A06: Vulnerable Components
- Track dependencies
- Monitor for CVEs
- Update regularly
- Remove unused dependencies

### A07: Authentication Failures
- Use multi-factor authentication
- Implement proper session management
- Use secure password policies
- Protect against brute force

### A08: Software and Data Integrity Failures
- Verify software integrity (checksums, signatures)
- Use secure CI/CD pipelines
- Validate serialized data
- Review code for tampering

### A09: Security Logging and Monitoring
- Log security-relevant events
- Ensure logs are protected
- Implement alerting
- Have an incident response plan

### A10: Server-Side Request Forgery (SSRF)
- Validate and sanitize URLs
- Use allowlists for destinations
- Block access to internal networks
- Disable unnecessary URL schemes

## LLM/AI Security Considerations

### Prompt Injection Prevention
- Separate system prompts from user input
- Validate and sanitize user prompts
- Use output validation
- Implement content filtering

### Sensitive Data in Prompts
- Don't include PII, secrets, or credentials in prompts
- Redact sensitive information before sending to LLMs
- Log prompts securely (redacted)
- Consider data residency requirements

### Output Validation
- Don't trust LLM output blindly
- Validate format and content
- Sanitize before displaying to users
- Implement rate limiting

### Model Security
- Protect model weights and configurations
- Use API keys/authentication
- Monitor for abuse
- Implement usage quotas
