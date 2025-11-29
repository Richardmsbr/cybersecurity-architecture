# Supply Chain Attack Incident Response Playbook

This playbook provides structured procedures for detecting, containing, and recovering from supply chain compromises affecting software dependencies, vendor systems, or third-party services.

---

## Attack Classification

### Supply Chain Attack Vectors

| Vector | Description | Examples |
|--------|-------------|----------|
| Software Dependencies | Compromised packages/libraries | npm, PyPI, Maven |
| Build Systems | CI/CD pipeline compromise | Jenkins, GitHub Actions |
| Code Repositories | Source code tampering | Commits, pull requests |
| Vendor Software | Legitimate software compromise | SolarWinds, Kaseya |
| Hardware | Firmware/hardware tampering | Implants, backdoors |
| Service Providers | MSP/CSP compromise | Cloud provider breach |
| Update Mechanisms | Hijacked updates | Auto-update exploitation |

### Severity Matrix

```
    SUPPLY CHAIN ATTACK SEVERITY

                        DEPLOYMENT SCOPE
                    Dev     Test    Staging  Production
    COMPONENT
    CRITICALITY

    Core              High    High    Critical  Critical
    Infrastructure

    Business          Medium  High    High      Critical
    Critical

    Standard          Low     Medium  High      High
    Application

    Non-Critical      Low     Low     Medium    Medium
```

---

## Detection Phase

### Detection Indicators

| Source | Indicators |
|--------|------------|
| Dependency scanning | New vulnerabilities, suspicious packages |
| Build system | Unexpected build changes, new dependencies |
| Network | Unusual outbound connections, C2 traffic |
| Endpoint | New processes, file changes |
| Threat intelligence | Vendor compromise announcements |
| Code review | Unexpected changes, obfuscated code |

### Detection Sources

```
    SUPPLY CHAIN COMPROMISE DETECTION

    Software Composition Analysis:
    +----------------------------------+
    | Dependency vulnerability scans   |
    | Version pinning violations       |
    | New transitive dependencies      |
    | Checksum mismatches              |
    +----------------------------------+

    Build Pipeline Monitoring:
    +----------------------------------+
    | Build artifact changes           |
    | Pipeline configuration changes   |
    | Unauthorized access              |
    | Unexpected network calls         |
    +----------------------------------+

    Runtime Monitoring:
    +----------------------------------+
    | Unexpected process spawning      |
    | Anomalous network connections    |
    | File system modifications        |
    | Memory injection                 |
    +----------------------------------+

    Threat Intelligence:
    +----------------------------------+
    | Vendor breach notifications      |
    | CVE announcements                |
    | Industry alerts                  |
    | Package maintainer compromise    |
    +----------------------------------+
```

### Initial Assessment

| Question | Investigation Method |
|----------|---------------------|
| What is compromised? | Vendor notification, threat intel |
| What versions affected? | Version analysis, vendor advisory |
| Where is it deployed? | Asset inventory, CMDB |
| Is it actively exploited? | Log analysis, IOC search |
| What is the blast radius? | Dependency mapping |

---

## Containment Phase

### Immediate Actions

| Priority | Action | Method |
|----------|--------|--------|
| 1 | Isolate affected systems | Network segmentation |
| 2 | Block malicious indicators | Firewall, proxy rules |
| 3 | Stop affected services | Service management |
| 4 | Prevent further deployment | Pipeline lockdown |
| 5 | Notify stakeholders | Communication plan |

### Dependency Containment

```
    DEPENDENCY CONTAINMENT WORKFLOW

    1. Identify Affected Package
       - Package name and version
       - All systems with dependency

    2. Block Package Distribution
       - Internal package registry
       - Build system lockdown
       - Deployment freeze

    3. Identify Downstream Impact
       - Direct dependencies
       - Transitive dependencies
       - Container images

    4. Isolate Affected Systems
       - Network isolation
       - Service shutdown if needed
       - Enhanced monitoring
```

### Vendor Software Containment

| Action | Implementation |
|--------|---------------|
| Isolate vendor software | Network segmentation |
| Block vendor network access | Firewall rules |
| Disable auto-updates | Update settings |
| Disconnect vendor integrations | API/service disconnection |
| Review vendor access | Access audit |

### Build System Containment

| Step | Action |
|------|--------|
| 1 | Freeze all deployments |
| 2 | Revoke pipeline credentials |
| 3 | Isolate build infrastructure |
| 4 | Audit recent builds |
| 5 | Verify build artifacts |

---

## Investigation Phase

### Scope Determination

```
    BLAST RADIUS ANALYSIS

    Direct Impact:
    +----------------------------------+
    | Systems with compromised         |
    | component installed              |
    +----------------------------------+
              |
              v
    Indirect Impact:
    +----------------------------------+
    | Systems connected to             |
    | compromised systems              |
    +----------------------------------+
              |
              v
    Data Impact:
    +----------------------------------+
    | Data accessible from             |
    | compromised systems              |
    +----------------------------------+
              |
              v
    Credential Impact:
    +----------------------------------+
    | Credentials stored on/used by    |
    | compromised systems              |
    +----------------------------------+
```

### Asset Identification

| Component | Identification Method |
|-----------|----------------------|
| Applications | Dependency scanning |
| Containers | Image scanning |
| Infrastructure | Configuration management |
| Endpoints | Endpoint detection |
| Cloud | Cloud security posture |

### Timeline Analysis

| Phase | Investigation |
|-------|---------------|
| Initial compromise | When was component compromised? |
| Distribution | When was it distributed to org? |
| Installation | When was it installed? |
| Activation | When did malicious activity start? |
| Discovery | When was it detected? |

### Malicious Capability Analysis

| Capability | Detection Method |
|------------|------------------|
| Backdoor | Code analysis, network monitoring |
| Data exfiltration | Network traffic analysis |
| Credential theft | Memory analysis, log review |
| Lateral movement | Network flow analysis |
| Persistence | System analysis |

---

## Eradication Phase

### Removal Procedures

| Component Type | Removal Method |
|----------------|----------------|
| Package dependency | Update to clean version, remove |
| Container image | Rebuild with clean base |
| Vendor software | Uninstall, replace |
| Build artifact | Rebuild from verified source |
| System compromise | Reimage/rebuild |

### Verification Steps

```
    ERADICATION VERIFICATION

    1. Component Removal
       [ ] Compromised package removed
       [ ] All instances identified and cleaned
       [ ] Dependencies verified

    2. System Verification
       [ ] No remaining malicious code
       [ ] No persistence mechanisms
       [ ] No unauthorized access

    3. Credential Rotation
       [ ] API keys rotated
       [ ] Service accounts reset
       [ ] Access tokens revoked

    4. Configuration Verification
       [ ] No unauthorized changes
       [ ] Security settings restored
       [ ] Logging enabled
```

### Safe Package Restoration

| Step | Action |
|------|--------|
| 1 | Verify clean version available |
| 2 | Check version hash/signature |
| 3 | Test in isolated environment |
| 4 | Deploy to non-production |
| 5 | Verify functionality |
| 6 | Deploy to production |

---

## Recovery Phase

### Service Restoration

| Priority | Systems | Validation |
|----------|---------|------------|
| 1 | Security infrastructure | Security testing |
| 2 | Core business services | Functional testing |
| 3 | Supporting services | Integration testing |
| 4 | Non-critical services | Basic validation |

### Build Pipeline Recovery

```
    BUILD PIPELINE RECOVERY

    1. Audit and Clean
       - Review all pipeline configurations
       - Verify source code integrity
       - Check secrets management

    2. Rebuild Trust
       - Rotate all credentials
       - Regenerate signing keys
       - Update access controls

    3. Staged Restoration
       - Rebuild in isolated environment
       - Verify artifact integrity
       - Gradual deployment

    4. Enhanced Monitoring
       - Build process logging
       - Artifact verification
       - Runtime monitoring
```

### Vendor Relationship Management

| Action | Purpose |
|--------|---------|
| Demand incident report | Understand impact |
| Review security practices | Assess future risk |
| Update contract terms | Include security requirements |
| Implement monitoring | Detect future issues |
| Consider alternatives | Reduce dependency |

---

## Communication

### Internal Communication

| Audience | Content | Timing |
|----------|---------|--------|
| Executive team | Business impact, risk | Immediate |
| IT teams | Technical details, actions | Immediate |
| Development | Package/code changes | Within hours |
| All employees | Impact on services | As appropriate |

### External Communication

| Audience | Circumstances | Content |
|----------|---------------|---------|
| Customers | If affected | Impact and remediation |
| Regulators | If required | Incident details |
| Partners | If integration affected | Status and timeline |
| Press | If public | Prepared statement |

### Vendor Communication

| Type | Purpose |
|------|---------|
| Initial notification | Confirm and get details |
| Status updates | Ongoing information |
| Technical coordination | Remediation assistance |
| Post-incident | Lessons learned, improvements |

---

## Post-Incident Activities

### Lessons Learned

| Category | Questions |
|----------|-----------|
| Detection | How was it discovered? Could we detect sooner? |
| Prevention | What controls failed? |
| Response | Was response timely and effective? |
| Vendor management | What due diligence was missing? |
| Architecture | How can we reduce blast radius? |

### Security Improvements

| Area | Improvements |
|------|-------------|
| Dependency management | Pinning, verification, scanning |
| Build security | Isolated builds, artifact signing |
| Vendor assessment | Enhanced due diligence |
| Monitoring | Supply chain specific detection |
| Architecture | Isolation, least privilege |

### Vendor Security Assessment

```
    VENDOR SECURITY ASSESSMENT

    Pre-Engagement:
    [ ] Security questionnaire
    [ ] SOC 2 report review
    [ ] Penetration test results
    [ ] Incident response capabilities

    Ongoing:
    [ ] Regular security reviews
    [ ] Continuous monitoring
    [ ] Access reviews
    [ ] Compliance verification

    Contract Requirements:
    [ ] Security standards
    [ ] Incident notification
    [ ] Audit rights
    [ ] Termination provisions
```

---

## Prevention Program

### Dependency Security

| Control | Implementation |
|---------|---------------|
| Package pinning | Lock file, version pinning |
| Integrity verification | Checksum/signature validation |
| Private registry | Internal package mirror |
| Vulnerability scanning | Automated SCA |
| License compliance | License scanning |

### Build Security

| Control | Implementation |
|---------|---------------|
| Isolated builds | Ephemeral build environments |
| Least privilege | Minimal build permissions |
| Artifact signing | Code signing |
| Build reproducibility | Reproducible builds |
| Audit logging | Complete build logs |

### Vendor Management

| Control | Implementation |
|---------|---------------|
| Due diligence | Security assessment |
| Contractual requirements | Security clauses |
| Continuous monitoring | Vendor risk monitoring |
| Access management | Least privilege access |
| Exit strategy | Vendor replacement plan |

---

## References

- NIST SP 800-161 Cyber Supply Chain Risk Management
- CISA Software Supply Chain Security Guidance
- SLSA (Supply-chain Levels for Software Artifacts)
- OpenSSF Scorecard

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
