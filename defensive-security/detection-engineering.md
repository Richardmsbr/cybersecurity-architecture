# Detection Engineering Guide

## Overview

Detection engineering is the practice of building and maintaining detection capabilities to identify adversary behavior.

---

## Detection Development Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  DETECTION DEVELOPMENT LIFECYCLE                            │
│                                                                             │
│  1. RESEARCH                                                                │
│     • Study threat intelligence                                             │
│     • Analyze MITRE ATT&CK techniques                                       │
│     • Review incident reports                                               │
│                                                                             │
│  2. HYPOTHESIS                                                              │
│     • Define adversary behavior                                             │
│     • Identify data sources needed                                          │
│     • Determine detection logic                                             │
│                                                                             │
│  3. DEVELOP                                                                 │
│     • Write detection rule                                                  │
│     • Test against known-bad samples                                        │
│     • Validate against production data                                      │
│                                                                             │
│  4. VALIDATE                                                                │
│     • False positive analysis                                               │
│     • Performance testing                                                   │
│     • Coverage assessment                                                   │
│                                                                             │
│  5. DEPLOY                                                                  │
│     • Push to production SIEM                                               │
│     • Configure alerting                                                    │
│     • Document response procedures                                          │
│                                                                             │
│  6. MAINTAIN                                                                │
│     • Monitor effectiveness                                                 │
│     • Tune for false positives                                              │
│     • Update for new variants                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## SIGMA Rules

### Rule Structure

```yaml
title: Suspicious PowerShell Execution
id: abc123-def456-ghi789
status: stable
description: Detects suspicious PowerShell command execution
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Security Team
date: 2024/01/15
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
            - 'IEX'
            - 'Invoke-Expression'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

---

## YARA Rules

### Basic Rule Structure

```yara
rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Detects Base64 encoded PowerShell"
        author = "Security Team"
        severity = "high"
        
    strings:
        $enc1 = "-enc" ascii nocase
        $enc2 = "-EncodedCommand" ascii nocase
        $b64 = /[A-Za-z0-9+\/=]{50,}/
        
    condition:
        ($enc1 or $enc2) and $b64
}

rule Webshell_Generic
{
    meta:
        description = "Generic webshell detection"
        
    strings:
        $php1 = "<?php" ascii
        $func1 = "eval(" ascii
        $func2 = "system(" ascii
        $func3 = "shell_exec(" ascii
        $func4 = "passthru(" ascii
        
    condition:
        $php1 and any of ($func*)
}
```

---

## Detection Coverage Matrix

| Technique | Log Source | Detection | Status |
|-----------|------------|-----------|--------|
| T1059.001 | Sysmon | PowerShell Logging | Active |
| T1003.001 | Sysmon | LSASS Access | Active |
| T1021.002 | Windows Security | SMB Lateral | Active |
| T1547.001 | Sysmon | Registry Run Keys | Active |
| T1071.001 | Proxy | HTTP C2 | Active |

---

## Testing Detections

### Atomic Red Team

```bash
# Test specific technique
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Test all techniques
Invoke-AtomicTest T1059.001
```

---

## Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| Detection Coverage | >80% | ATT&CK techniques covered |
| Mean Time to Detect | <1h | Time from attack to alert |
| False Positive Rate | <5% | FP / Total alerts |
| Alert Fidelity | >90% | True positives / Total alerts |

---

## References

- [SIGMA Project](https://github.com/SigmaHQ/sigma)
- [YARA Rules](https://yara.readthedocs.io/)
- [Atomic Red Team](https://atomicredteam.io/)
- [Detection Lab](https://github.com/clong/DetectionLab)
