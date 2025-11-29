# Ransomware Incident Response Playbook

## Overview

This playbook provides step-by-step procedures for responding to ransomware incidents. Time is critical - every minute counts to contain the spread and preserve evidence.

---

## Severity Classification

| Severity | Criteria | Response Time | Escalation |
|----------|----------|---------------|------------|
| **CRITICAL** | Domain controller encrypted, widespread infection | Immediate | CISO, CEO, Legal |
| **HIGH** | Multiple systems encrypted, critical services affected | < 15 min | Security Lead, IT Director |
| **MEDIUM** | Single system encrypted, non-critical | < 1 hour | Security Team |
| **LOW** | Ransomware detected but not executed | < 4 hours | Security Analyst |

---

## Initial Response Checklist

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ RANSOMWARE INITIAL RESPONSE (First 15 Minutes)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  □ 1. DO NOT PANIC - Follow procedures                                      │
│  □ 2. DO NOT pay ransom immediately                                         │
│  □ 3. DO NOT communicate with attacker without legal approval               │
│  □ 4. DO NOT turn off infected systems (preserve memory)                    │
│  □ 5. DO NOT delete ransom notes (evidence)                                 │
│                                                                             │
│  IMMEDIATE ACTIONS:                                                         │
│  ─────────────────────────────────────────────────────────────────────────  │
│  □ Disconnect infected systems from network (unplug cable, disable WiFi)    │
│  □ Isolate network segments if possible                                     │
│  □ Preserve ransom note and encrypted file samples                          │
│  □ Document everything with timestamps                                      │
│  □ Activate Incident Response Team                                          │
│  □ Begin forensic evidence collection                                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Detection & Identification

### Detection Sources

| Source | Indicators | Priority |
|--------|------------|----------|
| EDR | Process creation, file encryption | Critical |
| SIEM | Mass file modifications | Critical |
| User Reports | Ransom note, encrypted files | High |
| Network | C2 communication, lateral movement | High |
| File Integrity | Extension changes, file entropy | Medium |

### Ransomware Identification

```bash
#!/bin/bash
# ransomware-id.sh - Identify ransomware variant

# Collect ransom note
RANSOM_NOTE=$(find / -name "*.txt" -o -name "*.html" -newer /tmp/incident_start 2>/dev/null | head -5)

# Collect encrypted file samples
ENCRYPTED_SAMPLES=$(find / -name "*.encrypted" -o -name "*.locked" -o -name "*.crypted" 2>/dev/null | head -5)

# Get file extension patterns
echo "=== Ransom Notes ==="
echo "$RANSOM_NOTE"

echo "=== Encrypted Extensions ==="
find / -type f -mmin -60 2>/dev/null | grep -E '\.(encrypted|locked|crypted|enc|cry)$' | head -20

# Check against known variants
echo "=== Checking ID Ransomware ==="
echo "Upload samples to: https://id-ransomware.malwarehunterteam.com/"
```

### Common Ransomware Families

| Family | Extension | Ransom Note | Decryptor Available |
|--------|-----------|-------------|---------------------|
| LockBit 3.0 | .lockbit | Restore-My-Files.txt | No |
| BlackCat/ALPHV | .alphv | RECOVER-FILES.txt | No |
| Conti | .CONTI | readme.txt | Partial (leaked) |
| REvil/Sodinokibi | Random | [id]-readme.txt | Some variants |
| Ryuk | .RYK | RyukReadMe.html | No |
| Maze | Random | DECRYPT-FILES.txt | Discontinued |
| Hive | .hive | HOW_TO_DECRYPT.txt | FBI released |

---

## Phase 2: Containment

### Network Isolation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ CONTAINMENT STRATEGY                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TIER 1: Infected Host Isolation (Immediate)                                │
│  ├── Disconnect network cable                                               │
│  ├── Disable WiFi adapter                                                   │
│  ├── Block at switch port (shutdown interface)                              │
│  └── Add to quarantine VLAN                                                 │
│                                                                             │
│  TIER 2: Segment Isolation (< 15 min)                                       │
│  ├── Block inter-VLAN routing for affected segments                         │
│  ├── Implement emergency firewall rules                                     │
│  └── Disable VPN access from affected segments                              │
│                                                                             │
│  TIER 3: Enterprise Isolation (if spreading)                                │
│  ├── Block SMB (445) at core switches                                       │
│  ├── Block RDP (3389) internally                                            │
│  ├── Disable domain trust relationships                                     │
│  └── Consider full network shutdown                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Emergency Firewall Rules

```bash
# Block lateral movement protocols
# Windows Firewall (PowerShell)
New-NetFirewallRule -DisplayName "Block SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block
New-NetFirewallRule -DisplayName "Block RDP Inbound" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block
New-NetFirewallRule -DisplayName "Block WinRM Inbound" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Block
New-NetFirewallRule -DisplayName "Block WMI Inbound" -Direction Inbound -Protocol TCP -LocalPort 135 -Action Block

# Linux iptables
iptables -A INPUT -p tcp --dport 445 -j DROP
iptables -A INPUT -p tcp --dport 22 -s ! 10.0.0.0/8 -j DROP

# Cisco ASA
access-list EMERGENCY deny tcp any any eq 445
access-list EMERGENCY deny tcp any any eq 3389
```

### Credential Reset

```powershell
# Emergency credential reset procedures

# 1. Reset compromised accounts
$CompromisedUsers = @("user1", "user2", "admin1")
foreach ($user in $CompromisedUsers) {
    Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString "TempPass123!" -AsPlainText -Force)
    Set-ADUser -Identity $user -ChangePasswordAtLogon $true
    Disable-ADAccount -Identity $user
}

# 2. Reset KRBTGT (requires 2 resets, 10+ hours apart)
# WARNING: This will invalidate all Kerberos tickets
$NewPassword = [System.Web.Security.Membership]::GeneratePassword(32, 8)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)

# 3. Reset service accounts
Get-ADServiceAccount -Filter * | ForEach-Object {
    Reset-ADServiceAccountPassword -Identity $_.Name
}

# 4. Invalidate all sessions
# Azure AD
Get-AzureADUser -All $true | Revoke-AzureADUserAllRefreshToken
```

---

## Phase 3: Eradication

### Malware Removal

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ERADICATION CHECKLIST                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  □ Identify all infected systems (EDR, network logs)                        │
│  □ Identify initial access vector                                           │
│  □ Remove persistence mechanisms:                                           │
│     □ Scheduled tasks                                                       │
│     □ Registry run keys                                                     │
│     □ Services                                                              │
│     □ WMI subscriptions                                                     │
│     □ Startup folder items                                                  │
│  □ Remove malware binaries                                                  │
│  □ Remove C2 communication channels                                         │
│  □ Patch exploited vulnerabilities                                          │
│  □ Reset compromised credentials                                            │
│  □ Rebuild systems from known-good images                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Persistence Removal Script

```powershell
# Remove common ransomware persistence

# Scheduled Tasks
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -match "powershell|cmd|wscript|mshta"
} | Unregister-ScheduledTask -Confirm:$false

# Registry Run Keys
$RunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $RunKeys) {
    Get-ItemProperty $key | ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Value -match "powershell|cmd|temp|appdata"
        } | ForEach-Object {
            Remove-ItemProperty -Path $key -Name $_.Name -Force
        }
    }
}

# Malicious Services
Get-Service | Where-Object {
    $_.PathName -match "temp|appdata|programdata" -and
    $_.StartType -eq "Automatic"
} | Stop-Service -Force
```

---

## Phase 4: Recovery

### Recovery Decision Tree

```
                           RECOVERY OPTIONS
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                                                                         │
    │  Do you have verified backups?                                          │
    │           │                                                             │
    │     ┌─────┴─────┐                                                       │
    │     │           │                                                       │
    │    YES         NO                                                       │
    │     │           │                                                       │
    │     │           ├── Is decryptor available?                             │
    │     │           │         │                                             │
    │     │           │   ┌─────┴─────┐                                       │
    │     │           │  YES         NO                                       │
    │     │           │   │           │                                       │
    │     │           │   │           ├── Consider ransom payment             │
    │     │           │   │           │   (LAST RESORT)                       │
    │     │           │   │           │   • Legal review                      │
    │     │           │   │           │   • OFAC check                        │
    │     │           │   │           │   • No guarantee                      │
    │     │           │   │           │                                       │
    │     │           │   │           └── Accept data loss                    │
    │     │           │   │               Rebuild from scratch                │
    │     │           │   │                                                   │
    │     │           │   └── Use decryptor                                   │
    │     │               (NoMoreRansom.org)                                  │
    │     │                                                                   │
    │     └── RESTORE FROM BACKUP                                             │
    │         1. Verify backup integrity                                      │
    │         2. Scan backups for malware                                     │
    │         3. Restore to clean environment                                 │
    │         4. Validate data integrity                                      │
    │                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

### Backup Restoration Procedure

```bash
#!/bin/bash
# Ransomware recovery script

# 1. Verify backup integrity
echo "=== Verifying Backup Integrity ==="
BACKUP_PATH="/mnt/backup/latest"
sha256sum -c ${BACKUP_PATH}/checksums.sha256

# 2. Scan backup for malware
echo "=== Scanning Backup for Malware ==="
clamscan -r -i ${BACKUP_PATH}

# 3. Prepare clean environment
echo "=== Preparing Clean Environment ==="
# Boot from clean media, format affected drives

# 4. Restore from backup
echo "=== Restoring Data ==="
rsync -avz --progress ${BACKUP_PATH}/ /mnt/clean_system/

# 5. Validate restoration
echo "=== Validating Restoration ==="
diff -rq ${BACKUP_PATH} /mnt/clean_system/

# 6. Apply security updates before reconnecting
echo "=== Applying Security Updates ==="
apt update && apt upgrade -y
```

### System Rebuild Priority

| Priority | Systems | Recovery Time |
|----------|---------|---------------|
| 1 | Domain Controllers | 4-8 hours |
| 2 | DNS/DHCP | 2-4 hours |
| 3 | Critical Business Apps | 8-24 hours |
| 4 | Email/Communication | 4-8 hours |
| 5 | File Servers | 24-48 hours |
| 6 | User Workstations | 48-72 hours |

---

## Phase 5: Post-Incident

### Lessons Learned

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ POST-INCIDENT REVIEW                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Timeline Analysis                                                          │
│  ├── Initial compromise: [Date/Time]                                        │
│  ├── Dwell time: [Days]                                                     │
│  ├── Detection: [Date/Time]                                                 │
│  ├── Containment: [Date/Time]                                               │
│  ├── Eradication: [Date/Time]                                               │
│  └── Full recovery: [Date/Time]                                             │
│                                                                             │
│  Root Cause Analysis                                                        │
│  ├── Initial access vector: [Phishing/Exploit/Credentials]                  │
│  ├── Vulnerability exploited: [CVE/Misconfiguration]                        │
│  ├── Detection gaps: [What was missed]                                      │
│  └── Contributing factors: [Process/Technology/People]                      │
│                                                                             │
│  Impact Assessment                                                          │
│  ├── Systems affected: [Count]                                              │
│  ├── Data encrypted: [GB/TB]                                                │
│  ├── Downtime: [Hours]                                                      │
│  ├── Financial impact: [$]                                                  │
│  └── Reputational impact: [Assessment]                                      │
│                                                                             │
│  Improvement Actions                                                        │
│  ├── Technical controls to implement                                        │
│  ├── Process improvements                                                   │
│  ├── Training requirements                                                  │
│  └── Policy updates                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Reporting Requirements

| Regulation | Reporting Deadline | Authority |
|------------|-------------------|-----------|
| GDPR | 72 hours | Data Protection Authority |
| HIPAA | 60 days | HHS OCR |
| PCI-DSS | Immediately | Card Brands, Acquirer |
| SEC | 4 business days | SEC (if material) |
| State Breach Laws | Varies (24h-60 days) | State AG |

---

## Communication Templates

### Internal Communication

```
SUBJECT: [URGENT] Security Incident - Action Required

Team,

We are currently responding to a security incident affecting [SCOPE].

CURRENT STATUS:
- Incident declared at: [TIME]
- Systems affected: [LIST]
- Current phase: [Containment/Eradication/Recovery]

IMMEDIATE ACTIONS REQUIRED:
1. Do not access affected systems
2. Report any suspicious activity to security@company.com
3. Change your password at [URL]

WHAT WE ARE DOING:
- Incident Response Team activated
- Affected systems isolated
- Investigation in progress
- Recovery procedures initiated

NEXT UPDATE: [TIME]

Do not discuss this incident externally. Direct all media inquiries to [CONTACT].

Security Team
```

### External/Customer Communication

```
SUBJECT: Security Incident Notification

Dear [Customer/Partner],

We are writing to inform you of a security incident that may have affected your data.

WHAT HAPPENED:
On [DATE], we detected unauthorized access to our systems. Our investigation indicates that [DESCRIPTION].

WHAT INFORMATION WAS INVOLVED:
[List of data types potentially affected]

WHAT WE ARE DOING:
- Engaged leading cybersecurity firm for investigation
- Notified law enforcement
- Implementing additional security measures
- Offering [credit monitoring/identity protection]

WHAT YOU CAN DO:
1. Monitor your accounts for suspicious activity
2. Change passwords for any accounts using similar credentials
3. Enable multi-factor authentication where available

FOR MORE INFORMATION:
- Dedicated hotline: [PHONE]
- Email: [EMAIL]
- FAQ: [URL]

We sincerely apologize for any concern this may cause.

[EXECUTIVE NAME]
[TITLE]
```

---

## Ransomware Prevention Checklist

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ RANSOMWARE PREVENTION CONTROLS                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  BACKUP & RECOVERY                                                          │
│  □ 3-2-1 backup strategy (3 copies, 2 media, 1 offsite)                     │
│  □ Offline/air-gapped backups                                               │
│  □ Regular backup testing                                                   │
│  □ Immutable backup storage                                                 │
│                                                                             │
│  ENDPOINT PROTECTION                                                        │
│  □ EDR deployed to all endpoints                                            │
│  □ Application whitelisting                                                 │
│  □ Disable macros by default                                                │
│  □ Block script execution from user directories                             │
│                                                                             │
│  NETWORK SECURITY                                                           │
│  □ Network segmentation                                                     │
│  □ Block SMB across segments                                                │
│  □ Limit RDP access (VPN + MFA only)                                        │
│  □ Email security gateway                                                   │
│                                                                             │
│  ACCESS CONTROL                                                             │
│  □ Principle of least privilege                                             │
│  □ MFA for all users                                                        │
│  □ Privileged Access Management (PAM)                                       │
│  □ Regular access reviews                                                   │
│                                                                             │
│  VULNERABILITY MANAGEMENT                                                   │
│  □ Regular patching (< 30 days for critical)                                │
│  □ Vulnerability scanning                                                   │
│  □ Attack surface reduction                                                 │
│  □ Legacy system isolation                                                  │
│                                                                             │
│  USER AWARENESS                                                             │
│  □ Phishing awareness training                                              │
│  □ Simulated phishing campaigns                                             │
│  □ Incident reporting procedures                                            │
│  □ Social engineering awareness                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## References

- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [No More Ransom Project](https://www.nomoreransom.org/)
- [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [NIST Ransomware Risk Management](https://csrc.nist.gov/publications/detail/nistir/8374/final)
