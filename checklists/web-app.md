# Web Application Security Checklist

Comprehensive checklist based on OWASP guidelines for assessing web application security.

---

## Authentication

### Credential Management

- [ ] Strong password policy enforced (12+ characters)
- [ ] Password complexity requirements (upper, lower, number, special)
- [ ] Common/breached passwords blocked
- [ ] Account lockout after failed attempts
- [ ] Lockout duration appropriate (not permanent)
- [ ] Password reset requires identity verification
- [ ] Password change requires current password
- [ ] Passwords stored using strong hashing (bcrypt, Argon2)

### Multi-Factor Authentication

- [ ] MFA available for all users
- [ ] MFA enforced for sensitive operations
- [ ] MFA enforced for admin accounts
- [ ] Recovery codes securely generated
- [ ] MFA bypass controls in place

### Session Management

- [ ] Session tokens are cryptographically random
- [ ] Session tokens have sufficient entropy (128+ bits)
- [ ] Session timeout implemented (idle and absolute)
- [ ] Session invalidated on logout
- [ ] New session on authentication
- [ ] Session tokens not in URL
- [ ] Secure and HttpOnly cookie flags set
- [ ] SameSite cookie attribute configured

---

## Authorization

### Access Control

- [ ] Access control enforced server-side
- [ ] Deny by default
- [ ] Principle of least privilege applied
- [ ] Role-based access control implemented
- [ ] Direct object references validated
- [ ] Function-level access control enforced
- [ ] Sensitive operations require re-authentication

### Authorization Testing

- [ ] Horizontal privilege escalation tested
- [ ] Vertical privilege escalation tested
- [ ] IDOR vulnerabilities tested
- [ ] Admin functions protected
- [ ] API authorization consistent with UI

---

## Input Validation

### Server-Side Validation

- [ ] All input validated server-side
- [ ] Input length limits enforced
- [ ] Input type validation (expected format)
- [ ] Whitelist validation where possible
- [ ] File upload validation (type, size, content)
- [ ] URL validation for redirects

### Output Encoding

- [ ] HTML output encoding
- [ ] JavaScript output encoding
- [ ] URL encoding
- [ ] CSS encoding
- [ ] Context-appropriate encoding

---

## Injection Prevention

### SQL Injection

- [ ] Parameterized queries/prepared statements used
- [ ] ORM/query builder used safely
- [ ] Dynamic queries avoided
- [ ] Database user has minimal privileges
- [ ] Error messages don't expose SQL

### Command Injection

- [ ] System commands avoided where possible
- [ ] Input sanitized before command execution
- [ ] Commands parameterized (not string concatenation)
- [ ] Allowlist of permitted commands

### Other Injection

- [ ] LDAP injection prevented
- [ ] XML injection prevented
- [ ] XPath injection prevented
- [ ] Template injection prevented
- [ ] NoSQL injection prevented

---

## Cross-Site Scripting (XSS)

### Prevention

- [ ] Context-aware output encoding
- [ ] Content Security Policy implemented
- [ ] X-XSS-Protection header (legacy browsers)
- [ ] DOM manipulation uses safe methods
- [ ] User input not in dangerous sinks
- [ ] JavaScript frameworks used safely
- [ ] Rich text input sanitized

### Testing

- [ ] Reflected XSS tested
- [ ] Stored XSS tested
- [ ] DOM-based XSS tested
- [ ] XSS in error messages tested

---

## Cross-Site Request Forgery (CSRF)

- [ ] Anti-CSRF tokens implemented
- [ ] Tokens unique per session
- [ ] Tokens validated server-side
- [ ] SameSite cookie attribute set
- [ ] Referer/Origin header validation
- [ ] State-changing requests use POST
- [ ] Custom headers for API requests

---

## Security Headers

### Required Headers

- [ ] Content-Security-Policy
- [ ] X-Content-Type-Options: nosniff
- [ ] X-Frame-Options: DENY/SAMEORIGIN
- [ ] Strict-Transport-Security (HSTS)
- [ ] Referrer-Policy
- [ ] Permissions-Policy

### CSP Configuration

- [ ] No unsafe-inline for scripts
- [ ] No unsafe-eval
- [ ] Nonce or hash for inline scripts
- [ ] Report-uri configured
- [ ] Frame-ancestors defined

---

## Cryptography

### Transport Security

- [ ] TLS 1.2 or higher only
- [ ] Strong cipher suites only
- [ ] HSTS enabled with long max-age
- [ ] Certificate valid and trusted
- [ ] Certificate chain complete
- [ ] No mixed content

### Data Protection

- [ ] Sensitive data encrypted at rest
- [ ] Strong encryption algorithms (AES-256)
- [ ] Secure key management
- [ ] Passwords properly hashed
- [ ] Cryptographic functions from libraries (not custom)

---

## Error Handling and Logging

### Error Handling

- [ ] Generic error messages to users
- [ ] Detailed errors logged server-side
- [ ] Stack traces not exposed
- [ ] Error handling consistent
- [ ] Application fails securely

### Logging

- [ ] Security events logged
- [ ] Authentication events logged
- [ ] Access control failures logged
- [ ] Input validation failures logged
- [ ] Sensitive data not logged
- [ ] Log injection prevented
- [ ] Logs protected from tampering

---

## API Security

### API Authentication

- [ ] API keys/tokens properly managed
- [ ] Token expiration implemented
- [ ] Token revocation available
- [ ] OAuth 2.0/OIDC implemented correctly
- [ ] JWT validation complete

### API Protection

- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints
- [ ] Output encoding appropriate
- [ ] CORS configured restrictively
- [ ] API versioning implemented
- [ ] Swagger/OpenAPI secured

---

## File Handling

### File Upload

- [ ] File type validation (magic bytes)
- [ ] File extension validation
- [ ] File size limits enforced
- [ ] Files scanned for malware
- [ ] Files stored outside web root
- [ ] Uploaded files not executable
- [ ] Filename sanitization
- [ ] Direct access to uploads prevented

### File Download

- [ ] Path traversal prevented
- [ ] Access control enforced
- [ ] Content-Disposition header set
- [ ] X-Content-Type-Options set

---

## Business Logic

- [ ] Business rules enforced server-side
- [ ] Race conditions prevented
- [ ] Workflow sequence enforced
- [ ] Price/quantity manipulation prevented
- [ ] Abuse cases considered
- [ ] Rate limiting on sensitive functions

---

## Client-Side Security

- [ ] Sensitive logic on server
- [ ] Client-side validation duplicated server-side
- [ ] No secrets in client code
- [ ] Subresource Integrity for external resources
- [ ] Third-party scripts reviewed
- [ ] LocalStorage/SessionStorage usage reviewed

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
