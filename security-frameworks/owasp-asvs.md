# OWASP Application Security Verification Standard (ASVS)

The OWASP Application Security Verification Standard (ASVS) provides a basis for testing web application technical security controls and provides developers with a list of requirements for secure development.

---

## Overview

ASVS defines three security verification levels:

```
    ASVS VERIFICATION LEVELS

    Level 1: Opportunistic
    +-----------------------------------------------------------+
    | Low assurance - Automated testing                          |
    | Suitable for all applications                              |
    | Defends against basic attacks                              |
    +-----------------------------------------------------------+

    Level 2: Standard
    +-----------------------------------------------------------+
    | Reasonable assurance - Manual testing required             |
    | Applications handling sensitive data                       |
    | Defends against most risks                                 |
    +-----------------------------------------------------------+

    Level 3: Advanced
    +-----------------------------------------------------------+
    | High assurance - Expert manual testing                     |
    | Critical applications, high-value transactions             |
    | Defends against advanced attacks                           |
    +-----------------------------------------------------------+
```

---

## V1: Architecture, Design and Threat Modeling

### V1.1 Secure Software Development Lifecycle

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 1.1.1 | SDLC addresses security in all phases | | X | X |
| 1.1.2 | Threat modeling for design changes | | X | X |
| 1.1.3 | Security stories/features in backlog | | X | X |
| 1.1.4 | Application logic has defined trust boundaries | | X | X |
| 1.1.5 | High-level architecture documented | X | X | X |
| 1.1.6 | Cryptographic services centralized | | X | X |
| 1.1.7 | All authentication mechanisms documented | | X | X |

### V1.2 Authentication Architecture

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 1.2.1 | Unique user accounts, no shared accounts | X | X | X |
| 1.2.2 | Strong authentication using proven components | | X | X |
| 1.2.3 | Application uses single authentication mechanism | | X | X |
| 1.2.4 | All authentication pathways documented | | X | X |

### V1.4 Access Control Architecture

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 1.4.1 | Defined access control model | X | X | X |
| 1.4.2 | Trusted enforcement points | | X | X |
| 1.4.3 | Attribute or role-based access | | X | X |
| 1.4.4 | Access control fails securely | X | X | X |
| 1.4.5 | Sensitive data flows through minimal components | | X | X |

---

## V2: Authentication

### V2.1 Password Security

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 2.1.1 | Minimum 12 characters password | X | X | X |
| 2.1.2 | 64+ characters maximum permitted | X | X | X |
| 2.1.3 | No password truncation | X | X | X |
| 2.1.4 | Unicode characters allowed | X | X | X |
| 2.1.5 | Password checked against breach databases | X | X | X |
| 2.1.6 | Password strength meter provided | X | X | X |
| 2.1.7 | No composition rules | X | X | X |
| 2.1.8 | No periodic password changes required | X | X | X |
| 2.1.9 | No password hints | X | X | X |
| 2.1.10 | No knowledge-based authentication | X | X | X |
| 2.1.11 | Paste functionality allowed | X | X | X |
| 2.1.12 | Show/hide password toggle | X | X | X |

### V2.2 General Authenticator Security

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 2.2.1 | Anti-automation controls | X | X | X |
| 2.2.2 | Weak authenticator use prevented | | X | X |
| 2.2.3 | Secure notification of credential changes | X | X | X |
| 2.2.4 | Impersonation resistance | | X | X |
| 2.2.5 | Credential Service Provider integration verified | | X | X |
| 2.2.6 | Replay resistance | | | X |
| 2.2.7 | Intent verification for sensitive actions | | | X |

### V2.4 Credential Storage

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 2.4.1 | Passwords salted with 32+ bit salt | | X | X |
| 2.4.2 | Salt unique per credential | | X | X |
| 2.4.3 | Approved one-way key derivation function | | X | X |
| 2.4.4 | Iteration count configured appropriately | | X | X |
| 2.4.5 | Secret salt if using PBKDF2 | | X | X |

### V2.5 Credential Recovery

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 2.5.1 | System generated recovery secret | X | X | X |
| 2.5.2 | No recovery hints | X | X | X |
| 2.5.3 | Recovery passwords immediately expire | X | X | X |
| 2.5.4 | Shared accounts disabled | X | X | X |
| 2.5.5 | Administrator recovery requires MFA | | X | X |
| 2.5.6 | Recovery uses side-channel | X | X | X |
| 2.5.7 | OTP/MFA factors forgotten securely | X | X | X |

---

## V3: Session Management

### V3.1 Session Management Security

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 3.1.1 | Session token not exposed in URL | X | X | X |
| 3.1.2 | Session not displayed after auth | X | X | X |
| 3.1.3 | Session invalidated on logout | X | X | X |
| 3.1.4 | Absolute session timeout | X | X | X |

### V3.2 Session Binding

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 3.2.1 | New session on authentication | X | X | X |
| 3.2.2 | 128+ bit entropy session tokens | X | X | X |
| 3.2.3 | Cookies use Secure attribute | X | X | X |
| 3.2.4 | Cookies use HttpOnly attribute | X | X | X |
| 3.2.5 | Cookies use SameSite attribute | X | X | X |

### V3.3 Session Termination

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 3.3.1 | Logout terminates session | X | X | X |
| 3.3.2 | Authenticated users can terminate sessions | | X | X |
| 3.3.3 | Idle timeout after 15 minutes | | X | X |
| 3.3.4 | Absolute timeout after 12 hours | | X | X |

### V3.4 Cookie-based Session Management

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 3.4.1 | Cookie-based tokens use __Host- prefix | X | X | X |
| 3.4.2 | Cookie path attribute as restrictive as possible | X | X | X |
| 3.4.3 | Cookie SameSite=Strict by default | X | X | X |
| 3.4.4 | Cookies encrypted in transit | X | X | X |
| 3.4.5 | Session state server-side | | X | X |

---

## V4: Access Control

### V4.1 General Access Control Design

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 4.1.1 | Trusted enforcement point | X | X | X |
| 4.1.2 | Attribute/role-based access | X | X | X |
| 4.1.3 | Principle of least privilege | X | X | X |
| 4.1.4 | Access control decision logging | | X | X |
| 4.1.5 | Rate limiting | X | X | X |

### V4.2 Operation Level Access Control

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 4.2.1 | Data protected from unauthorized access | X | X | X |
| 4.2.2 | Data protection follows data classification | | X | X |
| 4.2.3 | Directory traversal protected | X | X | X |

### V4.3 Other Access Control

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 4.3.1 | Admin interfaces protected | X | X | X |
| 4.3.2 | Directory browsing disabled | X | X | X |
| 4.3.3 | Application denies by default | X | X | X |

---

## V5: Validation, Sanitization and Encoding

### V5.1 Input Validation

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 5.1.1 | HTTP parameter pollution defended | X | X | X |
| 5.1.2 | Framework auto-escapes user input | X | X | X |
| 5.1.3 | Structured data strongly typed | X | X | X |
| 5.1.4 | Untrusted data contextually output encoded | X | X | X |
| 5.1.5 | Safe/allowed character approach | X | X | X |

### V5.2 Sanitization and Sandboxing

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 5.2.1 | WYSIWYG editors sanitized | X | X | X |
| 5.2.2 | Unstructured data sanitized | X | X | X |
| 5.2.3 | User-controlled Markdown sanitized | X | X | X |
| 5.2.4 | SVG inline content restricted | X | X | X |
| 5.2.5 | Scripting in SVG disabled | X | X | X |
| 5.2.6 | Template injection protected | X | X | X |
| 5.2.7 | SSRF protected | X | X | X |
| 5.2.8 | Eval and dynamic code execution avoided | X | X | X |

### V5.3 Output Encoding and Injection Prevention

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 5.3.1 | Context-aware output encoding | X | X | X |
| 5.3.2 | HTML entities encoded | X | X | X |
| 5.3.3 | JavaScript context encoding | X | X | X |
| 5.3.4 | CSS context encoding | X | X | X |
| 5.3.5 | URL encoding for URL context | X | X | X |
| 5.3.6 | HTML attribute encoding | X | X | X |
| 5.3.7 | Parameterized queries prevent SQL injection | X | X | X |
| 5.3.8 | OS command injection protected | X | X | X |
| 5.3.9 | Local/remote file inclusion protected | X | X | X |
| 5.3.10 | XPath injection protected | X | X | X |

---

## V6: Stored Cryptography

### V6.1 Data Classification

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 6.1.1 | Regulated data identified | | X | X |
| 6.1.2 | Data classification scheme | | X | X |
| 6.1.3 | Sensitive data inventory | | X | X |

### V6.2 Algorithms

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 6.2.1 | FIPS 140-2 approved algorithms | X | X | X |
| 6.2.2 | Current strong algorithms | | X | X |
| 6.2.3 | Random values generated by approved RNG | X | X | X |
| 6.2.4 | RNG fails securely | | X | X |
| 6.2.5 | Known-weak algorithms prohibited | X | X | X |
| 6.2.6 | Nonces/IVs not reused | | X | X |
| 6.2.7 | Encrypted data authenticated | | | X |
| 6.2.8 | GCM/CCM for symmetric encryption | | | X |

### V6.3 Random Values

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 6.3.1 | Random values created by CSPRNG | X | X | X |
| 6.3.2 | GUIDs created by UUID v4 or higher | X | X | X |
| 6.3.3 | Random values unpredictable | | X | X |

### V6.4 Secret Management

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 6.4.1 | Secrets management solution | | X | X |
| 6.4.2 | Key material not exposed in code | X | X | X |

---

## V7: Error Handling and Logging

### V7.1 Log Content

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 7.1.1 | No sensitive data in logs | X | X | X |
| 7.1.2 | All authentication events logged | | X | X |
| 7.1.3 | All access control failures logged | | X | X |
| 7.1.4 | All input validation failures logged | | X | X |

### V7.2 Log Processing

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 7.2.1 | All log entries include timestamp | | X | X |
| 7.2.2 | All log entries can be correlated | | X | X |
| 7.2.3 | Logs protected from tampering | | | X |
| 7.2.4 | Time sources synchronized | | X | X |

### V7.3 Log Protection

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 7.3.1 | Logs encoded to prevent injection | | X | X |
| 7.3.2 | Log viewing tool protected | | X | X |
| 7.3.3 | Logs stored on different partition | | | X |
| 7.3.4 | Logs forwarded to SIEM | | | X |

### V7.4 Error Handling

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 7.4.1 | Generic error messages displayed | X | X | X |
| 7.4.2 | Exception handling consistent | | X | X |
| 7.4.3 | Last resort error handler exists | X | X | X |

---

## V8: Data Protection

### V8.1 General Data Protection

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 8.1.1 | Sensitive data protected from caching | | X | X |
| 8.1.2 | Server-side temp files have restricted access | | X | X |
| 8.1.3 | Sensitive data in URL avoided | X | X | X |
| 8.1.4 | Anti-caching headers for sensitive responses | X | X | X |
| 8.1.5 | Server-side sensitive data purged | | X | X |
| 8.1.6 | Clients can clear sensitive data | | X | X |

### V8.2 Client-side Data Protection

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 8.2.1 | Autocomplete disabled for sensitive fields | X | X | X |
| 8.2.2 | Sensitive data not stored in local storage | X | X | X |
| 8.2.3 | Sensitive data cleared on close | X | X | X |

### V8.3 Sensitive Private Data

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 8.3.1 | Data subject can request data deletion | X | X | X |
| 8.3.2 | Data subject can access their data | X | X | X |
| 8.3.3 | Data subject can export their data | X | X | X |
| 8.3.4 | Retention policies enforced | X | X | X |
| 8.3.5 | Unnecessary processing prevented | | X | X |
| 8.3.6 | Sensitive data collection has consent | | X | X |
| 8.3.7 | Sensitive fields masked in logs | X | X | X |
| 8.3.8 | Sensitive data inventoried | | X | X |

---

## V9: Communication Security

### V9.1 Client Communication Security

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 9.1.1 | TLS for all connections | X | X | X |
| 9.1.2 | TLS 1.2 or higher enforced | X | X | X |
| 9.1.3 | Strong cipher suites | X | X | X |
| 9.1.4 | HSTS header enabled | X | X | X |
| 9.1.5 | Preloaded HSTS | | | X |

### V9.2 Server Communication Security

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 9.2.1 | Trusted certificates for backend connections | | X | X |
| 9.2.2 | Encrypted backend connections | | X | X |
| 9.2.3 | External connections authenticated | | X | X |
| 9.2.4 | Certificate revocation verified | | X | X |
| 9.2.5 | Backend TLS connections verified | | | X |

---

## V10: Malicious Code

### V10.1 Code Integrity

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 10.1.1 | Code analysis tool detects malicious code | | | X |
| 10.1.2 | Application source not exposed | X | X | X |

### V10.2 Malicious Code Search

| # | Requirement | L1 | L2 | L3 |
|---|-------------|----|----|---|
| 10.2.1 | No undocumented features | X | X | X |
| 10.2.2 | No back doors | | X | X |
| 10.2.3 | No time bombs | | X | X |
| 10.2.4 | No logic bombs | | X | X |
| 10.2.5 | No Easter eggs | | X | X |
| 10.2.6 | No unauthorized data collection | | X | X |

---

## Implementation Checklist

```
ASVS IMPLEMENTATION PRIORITY

Phase 1: Foundation (L1)
[ ] Authentication basics
[ ] Session management
[ ] Input validation
[ ] Output encoding
[ ] TLS configuration

Phase 2: Standard (L2)
[ ] Advanced authentication
[ ] Cryptography
[ ] Data protection
[ ] Logging and monitoring
[ ] Error handling

Phase 3: Advanced (L3)
[ ] Threat modeling
[ ] Code review
[ ] Penetration testing
[ ] Advanced cryptography
[ ] Malicious code detection
```

---

## References

- OWASP ASVS 4.0
- OWASP Testing Guide
- NIST Digital Identity Guidelines

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
