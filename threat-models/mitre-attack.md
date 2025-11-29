# MITRE ATT&CK Framework

## Overview

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It provides a common language for describing adversary behavior.

---

## Enterprise ATT&CK Matrix

### Tactics (14 Categories)

| ID | Tactic | Description | Techniques |
|----|--------|-------------|------------|
| TA0043 | Reconnaissance | Gathering information | 10 |
| TA0042 | Resource Development | Establishing resources | 8 |
| TA0001 | Initial Access | Getting into the network | 9 |
| TA0002 | Execution | Running malicious code | 14 |
| TA0003 | Persistence | Maintaining presence | 19 |
| TA0004 | Privilege Escalation | Gaining higher permissions | 13 |
| TA0005 | Defense Evasion | Avoiding detection | 42 |
| TA0006 | Credential Access | Stealing credentials | 17 |
| TA0007 | Discovery | Understanding environment | 31 |
| TA0008 | Lateral Movement | Moving through network | 9 |
| TA0009 | Collection | Gathering target data | 17 |
| TA0011 | Command and Control | Communicating with compromised systems | 16 |
| TA0010 | Exfiltration | Stealing data | 9 |
| TA0040 | Impact | Disrupting operations | 14 |

---

## High-Impact Techniques

### Initial Access (TA0001)

#### T1566 - Phishing

```
TECHNIQUE: Phishing
TACTIC: Initial Access
PLATFORMS: Windows, macOS, Linux, Office 365, Google Workspace

SUB-TECHNIQUES:
├── T1566.001 - Spearphishing Attachment
│   ├── Malicious documents (Office macros, PDFs)
│   ├── Archive files (ZIP, RAR with executables)
│   └── ISO/IMG disk images
│
├── T1566.002 - Spearphishing Link
│   ├── Credential harvesting pages
│   ├── Drive-by downloads
│   └── OAuth consent phishing
│
└── T1566.003 - Spearphishing via Service
    ├── Social media messages
    ├── Collaboration platform DMs
    └── SMS phishing (Smishing)

DETECTION:
─────────────────────────────────────────────────────────────────────────────
• Email gateway analysis for suspicious attachments
• URL reputation and sandbox analysis
• User behavior analytics for credential submission
• Network traffic analysis for C2 beaconing

SIGMA RULE:
─────────────────────────────────────────────────────────────────────────────
title: Suspicious Office Document Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\mshta.exe'
    condition: selection
level: high

MITIGATIONS:
─────────────────────────────────────────────────────────────────────────────
• M1017 - User Training
• M1031 - Network Intrusion Prevention
• M1021 - Restrict Web-Based Content
• M1054 - Software Configuration (disable macros)
```

#### T1190 - Exploit Public-Facing Application

```
TECHNIQUE: Exploit Public-Facing Application
TACTIC: Initial Access
PLATFORMS: Windows, Linux, Containers, Network

COMMON VULNERABILITIES:
├── Web Application Vulnerabilities
│   ├── SQL Injection (SQLi)
│   ├── Remote Code Execution (RCE)
│   ├── Server-Side Request Forgery (SSRF)
│   ├── Deserialization
│   └── Path Traversal
│
├── Infrastructure Vulnerabilities
│   ├── VPN appliances (Pulse Secure, Fortinet)
│   ├── Exchange Server (ProxyShell, ProxyLogon)
│   ├── Log4Shell (CVE-2021-44228)
│   └── Spring4Shell (CVE-2022-22965)
│
└── API Vulnerabilities
    ├── Broken Authentication
    ├── Excessive Data Exposure
    └── Injection Attacks

DETECTION:
─────────────────────────────────────────────────────────────────────────────
• WAF alerts for exploit patterns
• Application logs for error spikes
• Network IDS signatures for known exploits
• File integrity monitoring for webshells

SIGMA RULE:
─────────────────────────────────────────────────────────────────────────────
title: Webshell Detection via Process Creation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\w3wp.exe'
            - '\httpd.exe'
            - '\nginx.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
    condition: selection
level: critical
```

---

### Execution (TA0002)

#### T1059 - Command and Scripting Interpreter

```
TECHNIQUE: Command and Scripting Interpreter
TACTIC: Execution
PLATFORMS: Windows, macOS, Linux, Network

SUB-TECHNIQUES:
├── T1059.001 - PowerShell
│   INDICATORS:
│   • -EncodedCommand, -enc, -e flags
│   • IEX (Invoke-Expression)
│   • DownloadString, DownloadFile
│   • Bypass execution policy
│
│   DETECTION:
│   • Script block logging (4104)
│   • Module logging (4103)
│   • PowerShell transcription
│
├── T1059.003 - Windows Command Shell
│   INDICATORS:
│   • cmd.exe /c with encoded commands
│   • certutil for downloads
│   • bitsadmin for persistence
│
├── T1059.005 - Visual Basic
│   INDICATORS:
│   • wscript.exe, cscript.exe execution
│   • VBS files in temp directories
│
└── T1059.007 - JavaScript
    INDICATORS:
    • Node.js for C2
    • JScript via wscript.exe

SIGMA RULES:
─────────────────────────────────────────────────────────────────────────────
title: Suspicious PowerShell Download
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
    condition: selection
level: high

---

title: Base64 Encoded PowerShell Command
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection
level: high
```

---

### Persistence (TA0003)

#### T1547 - Boot or Logon Autostart Execution

```
TECHNIQUE: Boot or Logon Autostart Execution
TACTIC: Persistence
PLATFORMS: Windows, macOS, Linux

SUB-TECHNIQUES:
├── T1547.001 - Registry Run Keys / Startup Folder
│   LOCATIONS:
│   • HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│   • HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│   • HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
│   • %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
│
├── T1547.004 - Winlogon Helper DLL
│   LOCATIONS:
│   • HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
│   • HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
│   • HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
│
├── T1547.005 - Security Support Provider
│   LOCATIONS:
│   • HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
│
└── T1547.009 - Shortcut Modification
    LOCATIONS:
    • LNK files in startup folders
    • Modified target paths

DETECTION:
─────────────────────────────────────────────────────────────────────────────
• Registry monitoring (Sysmon Event 13)
• File creation monitoring (Sysmon Event 11)
• Scheduled task enumeration
• Service creation monitoring

SIGMA RULE:
─────────────────────────────────────────────────────────────────────────────
title: Registry Run Key Modification
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains:
            - '\CurrentVersion\Run'
            - '\CurrentVersion\RunOnce'
    filter:
        Image|endswith:
            - '\msiexec.exe'
            - '\setup.exe'
    condition: selection and not filter
level: medium
```

#### T1053 - Scheduled Task/Job

```
TECHNIQUE: Scheduled Task/Job
TACTIC: Persistence, Privilege Escalation, Execution
PLATFORMS: Windows, Linux, macOS

SUB-TECHNIQUES:
├── T1053.002 - At
│   • Windows: at.exe (deprecated)
│   • Linux: at command
│
├── T1053.003 - Cron
│   LOCATIONS:
│   • /etc/crontab
│   • /etc/cron.d/
│   • /var/spool/cron/
│   • ~/.crontab
│
├── T1053.005 - Scheduled Task
│   TOOLS:
│   • schtasks.exe
│   • Task Scheduler GUI
│   • PowerShell ScheduledTasks module
│
└── T1053.007 - Container Orchestration Job
    • Kubernetes CronJobs
    • Docker scheduled containers

DETECTION QUERIES:
─────────────────────────────────────────────────────────────────────────────
-- Windows Security Log (Event 4698)
SELECT TimeCreated, TaskName, TaskContent
FROM SecurityEvents
WHERE EventID = 4698
AND TaskContent LIKE '%powershell%'

-- Sysmon Process Creation
SELECT *
FROM SysmonEvents
WHERE EventID = 1
AND Image LIKE '%schtasks.exe%'
AND CommandLine LIKE '%/create%'
```

---

### Credential Access (TA0006)

#### T1003 - OS Credential Dumping

```
TECHNIQUE: OS Credential Dumping
TACTIC: Credential Access
PLATFORMS: Windows, Linux, macOS

SUB-TECHNIQUES:
├── T1003.001 - LSASS Memory
│   TOOLS:
│   • Mimikatz (sekurlsa::logonpasswords)
│   • ProcDump
│   • Task Manager dump
│   • comsvcs.dll MiniDump
│
│   DETECTION:
│   • Sysmon Event 10 (Process Access to lsass.exe)
│   • Windows Defender Credential Guard alerts
│   • Memory access from unsigned processes
│
├── T1003.002 - Security Account Manager
│   TECHNIQUES:
│   • reg save HKLM\SAM
│   • Volume Shadow Copy
│   • ntdsutil
│
├── T1003.003 - NTDS
│   TECHNIQUES:
│   • ntdsutil "ac i ntds" "ifm" create full
│   • Volume Shadow Copy
│   • DCSync (Mimikatz)
│
│   DETECTION:
│   • Event 4662 (DS-Replication-Get-Changes)
│   • Network traffic to DC on port 135/445
│
├── T1003.004 - LSA Secrets
│   TOOLS:
│   • Mimikatz (lsadump::secrets)
│   • reg save HKLM\SECURITY
│
├── T1003.005 - Cached Domain Credentials
│   LOCATION:
│   • HKLM\SECURITY\Cache
│
├── T1003.006 - DCSync
│   REQUIREMENTS:
│   • Replicating Directory Changes
│   • Replicating Directory Changes All
│
│   DETECTION:
│   • Event 4662 with specific GUIDs
│   • Network monitoring for DCE/RPC
│
└── T1003.008 - /etc/passwd and /etc/shadow
    LINUX CREDENTIAL THEFT:
    • cat /etc/shadow (requires root)
    • unshadow for John the Ripper
    • /proc/[pid]/maps memory dumps

SIGMA RULES:
─────────────────────────────────────────────────────────────────────────────
title: LSASS Memory Access
logsource:
    product: windows
    category: sysmon
    definition: 'Sysmon Event 10'
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x143a'
    filter:
        SourceImage|endswith:
            - '\wmiprvse.exe'
            - '\svchost.exe'
    condition: selection and not filter
level: critical

---

title: DCSync Attack Detection
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
level: critical
```

---

### Defense Evasion (TA0005)

#### T1562 - Impair Defenses

```
TECHNIQUE: Impair Defenses
TACTIC: Defense Evasion
PLATFORMS: Windows, Linux, macOS, Cloud

SUB-TECHNIQUES:
├── T1562.001 - Disable or Modify Tools
│   TARGETS:
│   • Windows Defender (Set-MpPreference)
│   • EDR agents (service stop, file deletion)
│   • Sysmon (driver unload)
│   • Firewall rules
│
│   DETECTION:
│   • Service stop events (7036)
│   • Registry modifications
│   • Process termination of security tools
│
├── T1562.002 - Disable Windows Event Logging
│   TECHNIQUES:
│   • auditpol /clear
│   • wevtutil cl Security
│   • Disabling EventLog service
│
│   DETECTION:
│   • Event 1102 (audit log cleared)
│   • Service state changes
│
├── T1562.004 - Disable or Modify System Firewall
│   WINDOWS:
│   • netsh advfirewall set allprofiles state off
│   • Set-NetFirewallProfile -Enabled False
│
│   LINUX:
│   • iptables -F
│   • systemctl stop firewalld
│
└── T1562.006 - Indicator Blocking
    TECHNIQUES:
    • Hosts file modification
    • DNS sinkholing
    • Certificate pinning bypass

SIGMA RULE:
─────────────────────────────────────────────────────────────────────────────
title: Windows Defender Disabled via PowerShell
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains:
            - 'Set-MpPreference'
            - 'DisableRealtimeMonitoring'
            - 'DisableBehaviorMonitoring'
            - 'DisableIOAVProtection'
    condition: selection
level: high
```

---

### Lateral Movement (TA0008)

#### T1021 - Remote Services

```
TECHNIQUE: Remote Services
TACTIC: Lateral Movement
PLATFORMS: Windows, Linux

SUB-TECHNIQUES:
├── T1021.001 - Remote Desktop Protocol
│   PORT: 3389/TCP
│   DETECTION:
│   • Event 4624 (Logon Type 10)
│   • Network connections to 3389
│   • RDP session events (1149)
│
├── T1021.002 - SMB/Windows Admin Shares
│   SHARES:
│   • C$, ADMIN$, IPC$
│   TOOLS:
│   • PsExec, Impacket
│   DETECTION:
│   • Event 5140 (network share access)
│   • Event 4648 (explicit credentials)
│
├── T1021.003 - Distributed Component Object Model
│   TOOLS:
│   • Impacket dcomexec
│   • PowerShell COM objects
│   DETECTION:
│   • DCE/RPC network traffic
│   • DCOM process creation
│
├── T1021.004 - SSH
│   PORT: 22/TCP
│   DETECTION:
│   • SSH authentication logs
│   • Network connections to port 22
│   • Key-based auth vs password
│
├── T1021.005 - VNC
│   PORTS: 5900-5999/TCP
│
└── T1021.006 - Windows Remote Management
    PORTS: 5985 (HTTP), 5986 (HTTPS)
    TOOLS:
    • winrs.exe
    • PowerShell Enter-PSSession
    • evil-winrm

    DETECTION:
    • Event 4624 (Logon Type 3)
    • WinRM connection events
    • PowerShell remoting logs

DETECTION DASHBOARD:
─────────────────────────────────────────────────────────────────────────────
┌─────────────────────────────────────────────────────────────────────────────┐
│ LATERAL MOVEMENT DETECTION                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  RDP Connections (24h)          SMB Admin Share Access                      │
│  ┌────────────────────┐         ┌────────────────────┐                     │
│  │████████████ 156    │         │██████████████ 89   │                     │
│  │█████████ 122       │         │████████ 52         │                     │
│  │████████ 98         │         │███████ 41          │                     │
│  └────────────────────┘         └────────────────────┘                     │
│                                                                             │
│  WinRM Sessions                 PsExec Executions                           │
│  ┌────────────────────┐         ┌────────────────────┐                     │
│  │█████ 34            │         │██ 12 (ALERT)       │                     │
│  └────────────────────┘         └────────────────────┘                     │
│                                                                             │
│  ALERTS:                                                                    │
│  • [CRITICAL] PsExec detected from non-admin workstation                   │
│  • [HIGH] RDP from external IP to internal server                          │
│  • [MEDIUM] SMB lateral movement pattern detected                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Engineering

### SIGMA Rule Template

```yaml
title: [Rule Title]
id: [UUID]
status: [experimental|test|stable]
description: [Description]
references:
    - https://attack.mitre.org/techniques/TXXXX/
author: Security Team
date: YYYY/MM/DD
modified: YYYY/MM/DD

logsource:
    category: [process_creation|registry_set|file_creation|etc]
    product: [windows|linux|etc]
    service: [security|sysmon|etc]

detection:
    selection:
        FieldName|modifier:
            - 'value1'
            - 'value2'
    filter:
        ExcludeField: 'value'
    condition: selection and not filter

falsepositives:
    - Legitimate administrative activity

level: [informational|low|medium|high|critical]

tags:
    - attack.tactic
    - attack.tXXXX
```

### Detection Coverage Heatmap

```
                         DETECTION MATURITY

TACTIC              NONE    BASIC   GOOD    ADVANCED
─────────────────────────────────────────────────────
Reconnaissance      ░░░░    ████    ░░░░    ░░░░
Initial Access      ░░░░    ░░░░    ████    ░░░░
Execution           ░░░░    ░░░░    ░░░░    ████
Persistence         ░░░░    ░░░░    ████    ░░░░
Priv Escalation     ░░░░    ░░░░    ████    ░░░░
Defense Evasion     ░░░░    ████    ░░░░    ░░░░
Credential Access   ░░░░    ░░░░    ░░░░    ████
Discovery           ░░░░    ████    ░░░░    ░░░░
Lateral Movement    ░░░░    ░░░░    ████    ░░░░
Collection          ░░░░    ████    ░░░░    ░░░░
C2                  ░░░░    ░░░░    ████    ░░░░
Exfiltration        ░░░░    ████    ░░░░    ░░░░
Impact              ░░░░    ░░░░    ████    ░░░░

Legend: ░░░░ = Gap  ████ = Coverage
```

---

## Threat Intelligence Integration

### IOC Types and Sources

| IOC Type | Example | Sources |
|----------|---------|---------|
| IP Address | 192.0.2.1 | VirusTotal, AbuseIPDB, AlienVault |
| Domain | malware.example.com | DomainTools, PassiveTotal |
| File Hash | SHA256 | VirusTotal, Hybrid Analysis |
| URL | http://evil.com/payload | URLhaus, PhishTank |
| Email | attacker@evil.com | Have I Been Pwned |
| YARA Rule | rule Malware {...} | YARA Rules Repository |
| Sigma Rule | YAML detection | SigmaHQ |
| MITRE Technique | T1059.001 | ATT&CK Navigator |

### Threat Intel Platform Integration

```python
# MISP Integration Example
from pymisp import PyMISP

misp = PyMISP(url, key, ssl=True)

# Search for IOCs
result = misp.search(
    controller='attributes',
    type_attribute='ip-dst',
    value='192.0.2.1',
    pythonify=True
)

# Add new IOC
event = misp.new_event(
    distribution=0,
    threat_level_id=2,
    analysis=1,
    info='Suspected C2 Infrastructure'
)
misp.add_attribute(event, {'type': 'ip-dst', 'value': '192.0.2.1'})
```

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [SIGMA Rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [MITRE D3FEND](https://d3fend.mitre.org/)
