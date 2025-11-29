# Cyber Kill Chain Analysis

## Overview

The Cyber Kill Chain is a framework developed by Lockheed Martin that identifies the stages of a cyber attack. Understanding each phase helps defenders identify and stop attacks earlier in the chain.

---

## Kill Chain Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CYBER KILL CHAIN                                    │
│                                                                             │
│  PHASE 1: RECONNAISSANCE                                                    │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Target research and identification                                       │
│  • Email harvesting, social engineering                                     │
│  • Technology stack enumeration                                             │
│  DETECTION: DNS queries, web traffic analysis, OSINT monitoring             │
│                                                                             │
│  PHASE 2: WEAPONIZATION                                                     │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Creating malicious payload                                               │
│  • Coupling exploit with backdoor                                           │
│  • Preparing delivery mechanism                                             │
│  DETECTION: Threat intelligence, malware analysis                           │
│                                                                             │
│  PHASE 3: DELIVERY                                                          │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Phishing emails, watering hole sites                                     │
│  • USB drop, direct network exploitation                                    │
│  DETECTION: Email gateway, web proxy, IDS/IPS                               │
│                                                                             │
│  PHASE 4: EXPLOITATION                                                      │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Triggering vulnerability                                                 │
│  • Code execution on target                                                 │
│  DETECTION: EDR, application logs, exploit signatures                       │
│                                                                             │
│  PHASE 5: INSTALLATION                                                      │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Installing malware/RAT                                                   │
│  • Establishing persistence                                                 │
│  DETECTION: File integrity, registry monitoring, endpoint detection         │
│                                                                             │
│  PHASE 6: COMMAND & CONTROL                                                 │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Establishing communication channel                                       │
│  • Remote access to target                                                  │
│  DETECTION: Network traffic analysis, DNS monitoring, proxy logs            │
│                                                                             │
│  PHASE 7: ACTIONS ON OBJECTIVES                                             │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • Data exfiltration, destruction                                           │
│  • Lateral movement, privilege escalation                                   │
│  DETECTION: DLP, UEBA, SIEM correlation                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Opportunities

| Phase | Detection Method | Tools |
|-------|-----------------|-------|
| Reconnaissance | DNS monitoring, web analytics | Passive DNS, SIEM |
| Weaponization | Threat intelligence | TIP platforms |
| Delivery | Email filtering, web proxy | Email GW, Proxy |
| Exploitation | EDR, IDS/IPS | CrowdStrike, Snort |
| Installation | File integrity, registry | OSSEC, Sysmon |
| C2 | Network analysis | Zeek, NDR |
| Actions | DLP, UEBA | Varonis, Exabeam |

---

## Defense Strategies

### Left of Boom (Prevent)

- Security awareness training
- Patch management
- Email security
- Web filtering
- Network segmentation

### Right of Boom (Detect & Respond)

- EDR deployment
- SIEM monitoring
- Threat hunting
- Incident response
- Forensic capability

---

## References

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
