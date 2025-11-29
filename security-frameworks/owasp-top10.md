# OWASP Top 10 (2021) Security Guide

## Overview

The OWASP Top 10 is a standard awareness document representing the most critical security risks to web applications.

---

## A01:2021 - Broken Access Control

### Description
Access control enforces policy such that users cannot act outside of their intended permissions.

### Examples
- IDOR (Insecure Direct Object References)
- Bypassing access control by modifying URL
- Privilege escalation

### Prevention
```python
# Always verify authorization server-side
@require_permission('admin')
def admin_panel(request):
    # Verify user has admin role
    if not request.user.is_admin:
        raise PermissionDenied()
```

---

## A02:2021 - Cryptographic Failures

### Description
Failures related to cryptography which often lead to sensitive data exposure.

### Prevention
- Use TLS 1.2+ for all connections
- Encrypt sensitive data at rest (AES-256)
- Use strong password hashing (bcrypt, Argon2)
- Rotate encryption keys regularly

---

## A03:2021 - Injection

### Description
User-supplied data is not validated, filtered, or sanitized by the application.

### Prevention
```python
# Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Never concatenate user input
# BAD: f"SELECT * FROM users WHERE id = {user_id}"
```

---

## A04:2021 - Insecure Design

### Description
Missing or ineffective control design. Requires threat modeling and secure design patterns.

### Prevention
- Establish secure development lifecycle
- Use threat modeling
- Reference architectures
- Security requirements

---

## A05:2021 - Security Misconfiguration

### Description
Insecure default configurations, incomplete configurations, open cloud storage.

### Prevention
```yaml
# Disable debug mode in production
DEBUG: false
SECRET_KEY: ${RANDOM_SECRET}

# Security headers
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
```

---

## A06:2021 - Vulnerable Components

### Description
Using components with known vulnerabilities.

### Prevention
- Regular dependency scanning
- Automated updates
- Remove unused dependencies

---

## A07:2021 - Authentication Failures

### Description
Confirmation of user identity, authentication, and session management.

### Prevention
- Implement MFA
- Use strong password policies
- Secure session management
- Protect against brute force

---

## A08:2021 - Software Integrity Failures

### Description
Code and infrastructure that does not protect against integrity violations.

### Prevention
- Use signed packages
- Verify checksums
- CI/CD pipeline security
- Code signing

---

## A09:2021 - Security Logging Failures

### Description
Without logging and monitoring, breaches cannot be detected.

### Prevention
- Log authentication events
- Log access control failures
- Centralize logs (SIEM)
- Set up alerting

---

## A10:2021 - SSRF

### Description
SSRF occurs when a web application fetches a remote resource without validating the URL.

### Prevention
```python
# Whitelist allowed domains
ALLOWED_HOSTS = ['api.trusted.com', 'cdn.company.com']

def fetch_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise SecurityError("Forbidden host")
```

---

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
