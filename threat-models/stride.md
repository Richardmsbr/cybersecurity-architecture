# STRIDE Threat Modeling

## Overview

STRIDE is a threat modeling methodology developed by Microsoft that categorizes threats into six types. It provides a systematic approach to identify potential security threats during application design.

---

## STRIDE Categories

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           STRIDE FRAMEWORK                                  │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
│  │  SPOOFING   │  │  TAMPERING  │  │ REPUDIATION │                         │
│  │             │  │             │  │             │                         │
│  │ Pretending  │  │ Modifying   │  │ Denying     │                         │
│  │ to be       │  │ data or     │  │ actions     │                         │
│  │ someone     │  │ code        │  │ performed   │                         │
│  │ else        │  │             │  │             │                         │
│  │             │  │             │  │             │                         │
│  │ Violates:   │  │ Violates:   │  │ Violates:   │                         │
│  │ Authentica- │  │ Integrity   │  │ Non-        │                         │
│  │ tion        │  │             │  │ Repudiation │                         │
│  └─────────────┘  └─────────────┘  └─────────────┘                         │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                         │
│  │ INFORMATION │  │  DENIAL OF  │  │ ELEVATION   │                         │
│  │ DISCLOSURE  │  │   SERVICE   │  │    OF       │                         │
│  │             │  │             │  │ PRIVILEGE   │                         │
│  │ Exposing    │  │ Denying     │  │ Gaining     │                         │
│  │ data to     │  │ service to  │  │ capabil-    │                         │
│  │ unautho-    │  │ legitimate  │  │ ities       │                         │
│  │ rized       │  │ users       │  │ without     │                         │
│  │ parties     │  │             │  │ authori-    │                         │
│  │             │  │             │  │ zation      │                         │
│  │ Violates:   │  │ Violates:   │  │ Violates:   │                         │
│  │ Confiden-   │  │ Availa-     │  │ Authori-    │                         │
│  │ tiality     │  │ bility      │  │ zation      │                         │
│  └─────────────┘  └─────────────┘  └─────────────┘                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Threat Analysis

### S - Spoofing Identity

**Definition**: Pretending to be someone or something else to gain unauthorized access.

**Examples**:
| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| Credential Theft | Stealing usernames/passwords | Account takeover |
| Session Hijacking | Stealing session tokens | Unauthorized access |
| IP Spoofing | Forging source IP addresses | Bypass access controls |
| ARP Spoofing | Redirecting network traffic | Man-in-the-middle |
| DNS Spoofing | Redirecting DNS queries | Phishing, data theft |
| Certificate Forgery | Using fake certificates | Impersonation |

**Mitigations**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ SPOOFING MITIGATIONS                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Authentication Controls                                                    │
│  ├── Multi-Factor Authentication (MFA)                                      │
│  ├── Certificate-based authentication                                       │
│  ├── Hardware tokens (FIDO2, YubiKey)                                       │
│  └── Biometric verification                                                 │
│                                                                             │
│  Session Management                                                         │
│  ├── Secure session tokens (random, long)                                   │
│  ├── Session timeout and rotation                                           │
│  ├── Bind sessions to client fingerprint                                    │
│  └── Secure cookie attributes (HttpOnly, Secure, SameSite)                  │
│                                                                             │
│  Network Controls                                                           │
│  ├── IPsec / VPN with mutual authentication                                 │
│  ├── 802.1X port-based access control                                       │
│  ├── DNSSEC for DNS integrity                                               │
│  └── TLS/mTLS for all communications                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### T - Tampering

**Definition**: Modifying data, code, or configurations without authorization.

**Examples**:
| Attack Vector | Description | Impact |
|--------------|-------------|--------|
| SQL Injection | Modifying database queries | Data manipulation |
| Parameter Tampering | Modifying request parameters | Authorization bypass |
| Man-in-the-Middle | Intercepting and modifying traffic | Data corruption |
| Binary Patching | Modifying executable code | Malware insertion |
| Config Tampering | Changing system configurations | Security weakening |
| Log Tampering | Deleting or modifying logs | Covering tracks |

**Mitigations**:
```python
# Input Validation Example
from pydantic import BaseModel, validator
import hashlib

class TransactionRequest(BaseModel):
    amount: float
    account_id: str
    signature: str

    @validator('amount')
    def validate_amount(cls, v):
        if v <= 0 or v > 1000000:
            raise ValueError('Invalid amount')
        return round(v, 2)

    @validator('account_id')
    def validate_account(cls, v):
        if not v.isalnum() or len(v) != 10:
            raise ValueError('Invalid account ID')
        return v

    def verify_signature(self, secret_key: str) -> bool:
        """Verify HMAC signature to detect tampering"""
        expected = hmac.new(
            secret_key.encode(),
            f"{self.amount}{self.account_id}".encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected)
```

**Controls**:
- Input validation and sanitization
- Cryptographic integrity checks (HMAC, digital signatures)
- File integrity monitoring (AIDE, Tripwire)
- Database triggers for audit trails
- Immutable logs (append-only)
- Code signing and verification

---

### R - Repudiation

**Definition**: Denying having performed an action when there's no way to prove otherwise.

**Examples**:
| Scenario | Risk | Consequence |
|----------|------|-------------|
| Financial Transaction | User denies making purchase | Chargeback fraud |
| Contract Signing | Party denies agreement | Legal disputes |
| Admin Action | Admin denies configuration change | Accountability gap |
| Data Access | Employee denies data theft | Insider threat undetected |

**Mitigations**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ NON-REPUDIATION CONTROLS                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Logging & Audit                                                            │
│  ├── Comprehensive audit logs                                               │
│  │   ├── Who: User identity (authenticated)                                 │
│  │   ├── What: Action performed                                             │
│  │   ├── When: Timestamp (NTP synchronized)                                 │
│  │   ├── Where: Source IP, location                                         │
│  │   └── Result: Success/failure                                            │
│  ├── Log integrity protection (write-once storage)                          │
│  ├── Centralized log aggregation (SIEM)                                     │
│  └── Log retention policies                                                 │
│                                                                             │
│  Digital Signatures                                                         │
│  ├── Transaction signing                                                    │
│  ├── Document signing (PDF, DocuSign)                                       │
│  ├── Code signing certificates                                              │
│  └── Email signing (S/MIME, PGP)                                            │
│                                                                             │
│  Timestamps                                                                 │
│  ├── Trusted timestamping (RFC 3161)                                        │
│  ├── Blockchain anchoring                                                   │
│  └── Time-stamping authorities                                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Audit Log Format**:
```json
{
    "timestamp": "2024-01-15T10:30:45.123Z",
    "event_id": "uuid-v4",
    "user": {
        "id": "user123",
        "name": "john.doe@company.com",
        "ip_address": "192.168.1.100",
        "user_agent": "Mozilla/5.0...",
        "session_id": "sess_abc123"
    },
    "action": {
        "type": "data_export",
        "resource": "/api/customers",
        "method": "GET",
        "parameters": {"format": "csv", "date_range": "2024-01"}
    },
    "result": {
        "status": "success",
        "records_affected": 1500,
        "duration_ms": 234
    },
    "signature": "sha256_hmac_of_log_entry"
}
```

---

### I - Information Disclosure

**Definition**: Exposing information to unauthorized individuals.

**Examples**:
| Vector | Data at Risk | Impact |
|--------|-------------|--------|
| Error Messages | Stack traces, paths | Reconnaissance |
| Logs Exposure | Credentials, PII | Credential theft |
| Misconfigured Storage | S3 buckets, databases | Data breach |
| Side-Channel Attacks | Timing, cache | Key extraction |
| Memory Dumps | Heap, core dumps | Credential exposure |
| Network Sniffing | Unencrypted traffic | Data interception |

**Mitigations**:
```yaml
# Application Security Configuration
security:
  # Error Handling
  error_handling:
    show_stack_traces: false
    log_level: WARNING  # Not DEBUG in production
    custom_error_pages: true

  # Data Protection
  data_protection:
    encryption_at_rest: AES-256-GCM
    encryption_in_transit: TLS 1.3
    pii_masking: true
    data_classification: enabled

  # Access Controls
  access_control:
    principle_of_least_privilege: true
    need_to_know_basis: true
    data_loss_prevention: enabled

  # Headers
  security_headers:
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    Content-Security-Policy: "default-src 'self'"
    Strict-Transport-Security: "max-age=31536000; includeSubDomains"
    Cache-Control: "no-store, private"
```

**Data Classification Matrix**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ DATA CLASSIFICATION                                                         │
├─────────────────┬───────────────────┬───────────────────┬───────────────────┤
│ Classification  │ Examples          │ Controls Required │ Breach Impact     │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ PUBLIC          │ Marketing content │ None              │ None              │
│                 │ Press releases    │                   │                   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ INTERNAL        │ Employee directory│ Access control    │ Low               │
│                 │ Internal policies │ Basic encryption  │                   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ CONFIDENTIAL    │ Customer data     │ Encryption        │ Medium-High       │
│                 │ Financial reports │ MFA required      │ Regulatory        │
│                 │ Contracts         │ Audit logging     │                   │
├─────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ RESTRICTED      │ PII/PHI           │ Strong encryption │ Critical          │
│                 │ Payment data      │ DLP               │ Legal liability   │
│                 │ Trade secrets     │ Need-to-know      │ Existential       │
│                 │ Credentials       │ Privileged access │                   │
└─────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

---

### D - Denial of Service

**Definition**: Denying or degrading service to legitimate users.

**Examples**:
| Attack Type | Mechanism | Impact |
|------------|-----------|--------|
| Volumetric DDoS | Bandwidth exhaustion | Complete outage |
| Application DDoS | Resource exhaustion | Slow response |
| Algorithmic Complexity | Hash collision, ReDoS | CPU exhaustion |
| Resource Starvation | Connection pool exhaustion | Service unavailable |
| Logic Bombs | Triggered malicious code | System crash |

**Mitigations**:
```hcl
# AWS DDoS Protection
resource "aws_shield_protection" "main" {
  name         = "app-protection"
  resource_arn = aws_lb.main.arn
}

resource "aws_wafv2_web_acl" "main" {
  name  = "rate-limit-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "rate-limit"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      sampled_requests_enabled   = true
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
    }
  }
}

# Auto Scaling
resource "aws_appautoscaling_policy" "scale_out" {
  name               = "scale-out"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.main.resource_id
  scalable_dimension = aws_appautoscaling_target.main.scalable_dimension
  service_namespace  = aws_appautoscaling_target.main.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
```

**Defense Architecture**:
```
                         DDoS DEFENSE LAYERS
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                                                                         │
    │  LAYER 1: Edge (CDN/Cloud Provider)                                     │
    │  ├── BGP Flowspec                                                       │
    │  ├── Anycast distribution                                               │
    │  ├── Scrubbing centers                                                  │
    │  └── CloudFlare/AWS Shield/Akamai                                       │
    │                                                                         │
    │  LAYER 2: Network Perimeter                                             │
    │  ├── Rate limiting                                                      │
    │  ├── SYN cookies                                                        │
    │  ├── Connection limits                                                  │
    │  └── GeoIP blocking                                                     │
    │                                                                         │
    │  LAYER 3: Application                                                   │
    │  ├── WAF rules                                                          │
    │  ├── CAPTCHA/challenges                                                 │
    │  ├── Request throttling                                                 │
    │  └── Circuit breakers                                                   │
    │                                                                         │
    │  LAYER 4: Infrastructure                                                │
    │  ├── Auto-scaling                                                       │
    │  ├── Load balancing                                                     │
    │  ├── Caching                                                            │
    │  └── Redundancy                                                         │
    │                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

---

### E - Elevation of Privilege

**Definition**: Gaining capabilities without proper authorization.

**Examples**:
| Vector | Description | Impact |
|--------|-------------|--------|
| Vertical | User to admin | Full system control |
| Horizontal | User A to User B | Unauthorized access |
| Kernel Exploit | User to kernel | Complete compromise |
| Container Escape | Container to host | Infrastructure access |
| IDOR | Direct object reference | Data access |

**Mitigations**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PRIVILEGE ESCALATION PREVENTION                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Authorization Controls                                                     │
│  ├── Role-Based Access Control (RBAC)                                       │
│  ├── Attribute-Based Access Control (ABAC)                                  │
│  ├── Principle of least privilege                                           │
│  └── Just-in-time access                                                    │
│                                                                             │
│  Application Security                                                       │
│  ├── Server-side authorization checks                                       │
│  ├── Indirect object references                                             │
│  ├── Input validation                                                       │
│  └── Parameterized queries                                                  │
│                                                                             │
│  System Hardening                                                           │
│  ├── Remove unnecessary privileges                                          │
│  ├── Disable SUID/SGID where not needed                                     │
│  ├── Kernel hardening (seccomp, AppArmor, SELinux)                          │
│  └── Regular patching                                                       │
│                                                                             │
│  Container Security                                                         │
│  ├── Run as non-root                                                        │
│  ├── Read-only filesystem                                                   │
│  ├── Drop all capabilities                                                  │
│  └── No privilege escalation (allowPrivilegeEscalation: false)              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## STRIDE Threat Modeling Process

### Step-by-Step Methodology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     STRIDE THREAT MODELING PROCESS                          │
│                                                                             │
│  STEP 1: DECOMPOSE APPLICATION                                              │
│  ────────────────────────────────                                           │
│  • Identify entry points                                                    │
│  • Map data flows                                                           │
│  • Identify trust boundaries                                                │
│  • List assets                                                              │
│                                                                             │
│                           │                                                 │
│                           v                                                 │
│                                                                             │
│  STEP 2: CREATE DATA FLOW DIAGRAM (DFD)                                     │
│  ──────────────────────────────────────                                     │
│                                                                             │
│       ┌─────────┐        ┌─────────┐        ┌─────────┐                    │
│       │ External│  ───>  │  Web    │  ───>  │   API   │                    │
│       │  User   │        │  App    │        │ Server  │                    │
│       └─────────┘        └─────────┘        └────┬────┘                    │
│                              │                   │                          │
│                    ══════════╪═══════════════════╪══════ Trust Boundary     │
│                              │                   │                          │
│                              v                   v                          │
│                         ┌─────────┐        ┌─────────┐                     │
│                         │  Cache  │        │Database │                     │
│                         └─────────┘        └─────────┘                     │
│                                                                             │
│                           │                                                 │
│                           v                                                 │
│                                                                             │
│  STEP 3: IDENTIFY THREATS (PER ELEMENT)                                     │
│  ──────────────────────────────────────                                     │
│                                                                             │
│  Element        │ S │ T │ R │ I │ D │ E │                                  │
│  ───────────────┼───┼───┼───┼───┼───┼───┤                                  │
│  External User  │ ✓ │   │ ✓ │   │   │   │                                  │
│  Web App        │ ✓ │ ✓ │ ✓ │ ✓ │ ✓ │ ✓ │                                  │
│  API Server     │ ✓ │ ✓ │ ✓ │ ✓ │ ✓ │ ✓ │                                  │
│  Database       │   │ ✓ │ ✓ │ ✓ │ ✓ │   │                                  │
│  Data Flow      │   │ ✓ │   │ ✓ │ ✓ │   │                                  │
│                                                                             │
│                           │                                                 │
│                           v                                                 │
│                                                                             │
│  STEP 4: DOCUMENT & PRIORITIZE                                              │
│  ─────────────────────────────                                              │
│  • Calculate risk (DREAD scoring)                                           │
│  • Prioritize mitigations                                                   │
│  • Create security requirements                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Threat Documentation Template

```markdown
## Threat: [THREAT_ID]

**Category**: [S/T/R/I/D/E]
**Element**: [Component affected]
**Description**: [What the attacker can do]

### Attack Scenario
1. Attacker [action]
2. System [vulnerability]
3. Result: [impact]

### DREAD Score
| Factor | Score (1-10) | Justification |
|--------|--------------|---------------|
| Damage | | |
| Reproducibility | | |
| Exploitability | | |
| Affected Users | | |
| Discoverability | | |
| **Total** | **/50** | |

### Mitigations
| Control | Type | Priority |
|---------|------|----------|
| | Preventive | |
| | Detective | |
| | Corrective | |

### Residual Risk
[After mitigations are applied]
```

---

## References

- [Microsoft STRIDE](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
