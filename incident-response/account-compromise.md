# Account Compromise Incident Response Playbook

This playbook provides structured procedures for detecting, containing, and recovering from account compromise incidents involving unauthorized access to user credentials or session tokens.

---

## Compromise Classification

| Level | Description | Examples | Response Time |
|-------|-------------|----------|---------------|
| Critical | Admin/privileged account | Domain Admin, root, cloud admin | Immediate |
| High | Service account or executive | API keys, C-level accounts | < 30 min |
| Medium | Standard user with sensitive access | Finance, HR, developers | < 1 hour |
| Low | Standard user, limited access | General employees | < 4 hours |

---

## Detection Phase

### Detection Sources

```
    ACCOUNT COMPROMISE INDICATORS

    Authentication Systems:
    +----------------------------------+
    | Failed login attempts            |
    | Impossible travel alerts         |
    | New device/location login        |
    | MFA bypass attempts              |
    | Password spray patterns          |
    +----------------------------------+

    Identity Providers:
    +----------------------------------+
    | OAuth consent grants             |
    | Federation changes               |
    | MFA modifications                |
    | Recovery option changes          |
    +----------------------------------+

    Email Security:
    +----------------------------------+
    | Forwarding rule creation         |
    | Delegate access added            |
    | Unusual sending patterns         |
    | Inbox rule modifications         |
    +----------------------------------+

    Endpoint/Network:
    +----------------------------------+
    | Credential dumping tools         |
    | Pass-the-hash activity           |
    | Kerberos anomalies               |
    | VPN from unusual locations       |
    +----------------------------------+
```

### Indicators of Compromise

| Category | Indicator | Detection Method |
|----------|-----------|------------------|
| Authentication | Multiple failed logins | SIEM correlation |
| Authentication | Login from new location | UEBA, geo-IP |
| Authentication | Impossible travel | Identity provider |
| Authentication | MFA registration changes | Audit logs |
| Email | New forwarding rules | Email admin logs |
| Email | Inbox rules to hide messages | PowerShell/Graph API |
| Access | Unusual resource access | Access logs |
| Access | Off-hours activity | UEBA |
| Behavior | Mass data access | DLP, access logs |
| Behavior | Privilege escalation | PAM, AD logs |

### Triage Questions

| Question | Investigation |
|----------|---------------|
| Which account(s) affected? | Identity provider logs |
| When did compromise occur? | Timeline analysis |
| How was access obtained? | Authentication logs, phishing analysis |
| What was accessed? | Application/resource logs |
| Is attack ongoing? | Active session analysis |
| Are other accounts affected? | Lateral movement analysis |

---

## Containment Phase

### Immediate Actions

| Priority | Action | Method |
|----------|--------|--------|
| 1 | Disable compromised account | Identity provider |
| 2 | Revoke active sessions | Session management |
| 3 | Revoke OAuth tokens | Application admin |
| 4 | Reset credentials | Identity provider |
| 5 | Review and remove persistence | Email rules, delegates |

### Session Revocation Procedures

```
    SESSION REVOCATION

    Azure AD/Entra:
    1. Revoke-AzureADUserAllRefreshToken
    2. Set-AzureADUser -AccountEnabled $false
    3. Reset password
    4. Revoke app consent grants

    Google Workspace:
    1. Admin Console > Users > Security
    2. Sign out user from all sessions
    3. Reset password
    4. Review connected apps

    On-Premise AD:
    1. Disable account
    2. Reset password
    3. Invalidate Kerberos tickets
    4. Force group policy update

    Applications:
    1. Revoke API tokens
    2. Invalidate sessions
    3. Review connected services
```

### Email Security Lockdown

| Action | Command/Method |
|--------|----------------|
| Remove forwarding | Set-Mailbox -ForwardingAddress $null |
| Remove inbox rules | Get-InboxRule \| Remove-InboxRule |
| Remove delegates | Remove-MailboxPermission |
| Review sent items | Export recent sent mail |
| Review deleted items | Search recoverable items |

### Privileged Account Response

| Account Type | Additional Actions |
|--------------|-------------------|
| Domain Admin | Check for new accounts, GPO changes, DCSync |
| Cloud Admin | Review IAM changes, new roles, API keys |
| Service Account | Rotate keys, review usage, audit access |
| Database Admin | Audit queries, check for data export |

---

## Investigation Phase

### Timeline Construction

| Time Period | Data Sources |
|-------------|--------------|
| Pre-compromise | Phishing logs, credential exposure |
| Initial access | Authentication logs |
| Persistence | Email rules, OAuth grants |
| Actions | Resource access logs |
| Discovery | Current activity |

### Attack Vector Analysis

| Vector | Investigation |
|--------|---------------|
| Phishing | Email gateway logs, user reports |
| Credential stuffing | Failed login patterns |
| Password spray | Distributed failed logins |
| MFA bypass | Conditional access logs |
| Token theft | Session analysis |
| Malware | Endpoint telemetry |

### Lateral Movement Check

```
    LATERAL MOVEMENT ANALYSIS

    1. Review authentication patterns
       - Same source IP, different accounts
       - Sequential account access
       - Failed attempts followed by success

    2. Check for credential exposure
       - Hash extraction (LSASS)
       - Ticket extraction (Mimikatz)
       - Token theft

    3. Analyze accessed resources
       - SharePoint/OneDrive
       - File shares
       - Applications
       - Email

    4. Review privileged access
       - Admin portal access
       - Management consoles
       - Infrastructure access
```

### Impact Assessment

| Category | Assessment |
|----------|------------|
| Data accessed | File access logs, email access |
| Data exfiltrated | DLP logs, network traffic |
| Changes made | Audit logs, configuration changes |
| Persistence established | New accounts, rules, apps |
| Other accounts affected | Related compromise indicators |

---

## Eradication Phase

### Remove Attacker Access

| Persistence Type | Removal Action |
|------------------|----------------|
| Email forwarding | Remove forwarding rules |
| Inbox rules | Delete malicious rules |
| OAuth apps | Revoke consent grants |
| Delegates | Remove delegate access |
| MFA devices | Remove attacker MFA |
| API keys | Rotate/revoke keys |
| Recovery options | Remove unauthorized recovery |

### Credential Reset Procedures

| System | Reset Procedure |
|--------|-----------------|
| Active Directory | Reset password, reset AD tokens |
| Azure AD | Reset password, revoke sessions |
| Email | Reset password, review security |
| VPN | Reset credentials, review tokens |
| Applications | Reset app-specific passwords |
| Service accounts | Rotate credentials |

### Verify Clean State

```
    VERIFICATION CHECKLIST

    Authentication:
    [ ] No unauthorized sessions active
    [ ] Password successfully reset
    [ ] MFA devices verified as legitimate
    [ ] Recovery options verified

    Email:
    [ ] No unauthorized forwarding rules
    [ ] No unauthorized inbox rules
    [ ] No unauthorized delegates
    [ ] Sent items reviewed for abuse

    Applications:
    [ ] Unauthorized OAuth apps revoked
    [ ] API keys rotated
    [ ] Connected apps reviewed
    [ ] Session tokens revoked

    Access:
    [ ] Recent access patterns reviewed
    [ ] No unauthorized data access
    [ ] No persistence mechanisms
    [ ] No lateral movement detected
```

---

## Recovery Phase

### Account Restoration

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Generate new secure password | Complexity requirements |
| 2 | Re-enable account | Confirm access works |
| 3 | Re-register MFA | Verify MFA functional |
| 4 | Verify recovery options | Confirm legitimate |
| 5 | Confirm user access | User verification |
| 6 | Enable monitoring | Enhanced logging |

### User Communication

```
    USER NOTIFICATION TEMPLATE

    Subject: Security Notice - Account Recovery Required

    Your account was identified as potentially compromised.
    As a precaution, your account has been secured and
    your password has been reset.

    REQUIRED ACTIONS:
    1. Use the temporary password provided separately
    2. Create a new strong, unique password
    3. Re-register your MFA device
    4. Review your recent account activity
    5. Report any suspicious activity

    WHAT HAPPENED:
    [Brief, appropriate description]

    WHAT WE'RE DOING:
    [Investigation and protection measures]

    QUESTIONS:
    Contact [Security Team / Help Desk]
```

### Enhanced Monitoring

| Monitoring | Duration | Trigger |
|------------|----------|---------|
| Login activity | 30 days | Any authentication |
| Resource access | 30 days | Sensitive data access |
| Email activity | 30 days | Forwarding, rules |
| MFA changes | 90 days | Any MFA modification |

---

## Business Email Compromise Response

### BEC-Specific Indicators

| Indicator | Detection |
|-----------|-----------|
| Forwarding to external | Email admin logs |
| Invoice/wire fraud attempts | User reports |
| Executive impersonation | Email analysis |
| Vendor impersonation | Email headers |
| Reply-to manipulation | Header analysis |

### BEC Investigation

```
    BEC INVESTIGATION STEPS

    1. Identify compromised account
       - Review authentication logs
       - Identify unauthorized access

    2. Analyze email activity
       - Sent mail review
       - Reply chains
       - Attachment analysis

    3. Identify targets
       - Who received fraudulent emails
       - What was requested
       - What information was disclosed

    4. Financial impact
       - Wire transfer requests
       - Invoice modifications
       - Payment redirections

    5. Notification
       - Internal stakeholders
       - External targets
       - Financial institutions
```

### Financial Fraud Response

| Timeframe | Action |
|-----------|--------|
| 0-24 hours | Contact bank, attempt recall |
| 24-72 hours | File fraud report |
| 72+ hours | Law enforcement report |

---

## Prevention Measures

### Authentication Hardening

| Control | Implementation |
|---------|---------------|
| MFA | Required for all users |
| Conditional Access | Risk-based policies |
| Password policy | Strong, no reuse |
| Legacy auth | Block/disable |
| Session timeout | Appropriate duration |

### Detection Enhancement

| Capability | Implementation |
|------------|---------------|
| Impossible travel | Enable alerts |
| Anomalous activity | UEBA deployment |
| Forwarding rules | Automated detection |
| OAuth grants | Review/alerting |
| Privileged access | Enhanced monitoring |

---

## Metrics and KPIs

| Metric | Target |
|--------|--------|
| Time to detect | < 1 hour |
| Time to contain | < 30 minutes |
| Time to recover | < 4 hours |
| Accounts compromised | < 1 per 1000 users annually |

---

## References

- NIST SP 800-63 Digital Identity Guidelines
- Microsoft Security Best Practices
- CISA Account Compromise Response Guide

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
