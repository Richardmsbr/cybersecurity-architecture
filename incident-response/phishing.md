# Phishing Incident Response Playbook

## Overview

Playbook for responding to phishing attacks and credential compromise.

---

## Severity Classification

| Level | Criteria | Response Time |
|-------|----------|---------------|
| Critical | Executive targeted, credentials compromised | < 15 min |
| High | Multiple users clicked, data accessed | < 30 min |
| Medium | Single user clicked, no data access | < 2 hours |
| Low | Reported, not clicked | < 4 hours |

---

## Response Procedures

### Phase 1: Identification (< 15 min)

```
□ Confirm phishing attempt
  □ Review email headers
  □ Analyze URLs/attachments
  □ Check sender reputation

□ Identify affected users
  □ Search email logs for recipients
  □ Check proxy logs for clicks
  □ Review authentication logs
```

### Phase 2: Containment (< 30 min)

```
□ Block malicious indicators
  □ Block sender domain/IP at email gateway
  □ Block URL at web proxy
  □ Add to threat intelligence

□ Remove emails from mailboxes
  □ Exchange: Compliance Search & Delete
  □ O365: Content Search
  □ Google: Admin console deletion

□ If credentials compromised:
  □ Reset passwords immediately
  □ Terminate active sessions
  □ Enable MFA if not present
```

### Phase 3: Eradication (< 2 hours)

```
□ Scan affected systems for malware
□ Review authentication logs for lateral movement
□ Check for email forwarding rules
□ Review OAuth/App permissions
□ Search for persistence mechanisms
```

### Phase 4: Recovery

```
□ Restore access after password reset
□ Verify MFA enrollment
□ Monitor for suspicious activity
□ Update user security awareness
```

### Phase 5: Lessons Learned

```
□ Document timeline
□ Identify detection gaps
□ Update email filtering rules
□ Conduct targeted training
□ Report metrics
```

---

## Useful Commands

### Exchange/O365 Search

```powershell
# Search for phishing emails
Search-Mailbox -Identity * -SearchQuery "From:attacker@evil.com" -DeleteContent -Force

# Check forwarding rules
Get-InboxRule -Mailbox user@company.com | Where-Object {$_.ForwardTo -or $_.ForwardAsAttachmentTo}
```

### Google Workspace

```bash
# Admin SDK - Delete emails
GAM all users delete messages query "from:attacker@evil.com"

# Check filters
GAM user user@company.com show filters
```
