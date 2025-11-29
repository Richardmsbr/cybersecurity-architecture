# DDoS Attack Incident Response Playbook

This playbook provides structured procedures for detecting, mitigating, and recovering from Distributed Denial of Service (DDoS) attacks against organizational infrastructure and services.

---

## Attack Classification

### DDoS Attack Types

| Category | Type | Layer | Description |
|----------|------|-------|-------------|
| Volumetric | UDP Flood | L3/L4 | High bandwidth consumption |
| Volumetric | ICMP Flood | L3 | Ping flood attacks |
| Volumetric | Amplification | L3/L4 | DNS, NTP, SSDP reflection |
| Protocol | SYN Flood | L4 | TCP state exhaustion |
| Protocol | ACK Flood | L4 | Stateful firewall bypass |
| Protocol | Fragmentation | L3 | IP fragment attacks |
| Application | HTTP Flood | L7 | Web server resource exhaustion |
| Application | Slowloris | L7 | Connection exhaustion |
| Application | DNS Query | L7 | DNS server overload |

### Severity Matrix

```
    DDoS SEVERITY CLASSIFICATION

                          ATTACK BANDWIDTH
                    <1Gbps  1-10Gbps  10-100Gbps  >100Gbps
    SERVICE
    IMPACT

    Complete         High    Critical  Critical    Critical
    Outage

    Degraded         Medium  High      Critical    Critical
    Service

    Minimal          Low     Medium    High        Critical
    Impact

    No Impact        Low     Low       Medium      High
```

---

## Detection Phase

### Detection Sources

| Source | Indicators | Threshold |
|--------|------------|-----------|
| Network monitoring | Bandwidth spike | >80% capacity |
| IDS/IPS | Attack signatures | Alert threshold |
| Firewall | Connection rate | >1000 new/sec |
| Load balancer | Backend health | >50% unhealthy |
| Application | Response time | >5 second latency |
| CDN/DDoS protection | Attack detection | Provider threshold |

### Attack Indicators

```
    DDoS ATTACK INDICATORS

    Network Layer:
    +--------------------------------+
    | Sudden bandwidth increase      |
    | Unusual geographic sources     |
    | High packet-per-second rate    |
    | Fragmented packets             |
    | Spoofed source addresses       |
    +--------------------------------+

    Transport Layer:
    +--------------------------------+
    | SYN flood patterns             |
    | High connection rate           |
    | Connection state exhaustion    |
    | RST/FIN anomalies              |
    +--------------------------------+

    Application Layer:
    +--------------------------------+
    | High request rate              |
    | Unusual URL patterns           |
    | Bot-like behavior              |
    | Cache bypass patterns          |
    | Slow connection attacks        |
    +--------------------------------+
```

### Initial Assessment

| Question | How to Determine |
|----------|------------------|
| What is being targeted? | Traffic analysis, logs |
| What type of attack? | Packet analysis, signatures |
| What is the attack volume? | Bandwidth monitoring |
| What is the source? | IP analysis, geographic data |
| Is this a diversion? | Monitor other services |

---

## Response Phase

### Immediate Actions (0-15 minutes)

| Step | Action | Owner |
|------|--------|-------|
| 1 | Confirm attack (not capacity issue) | NOC |
| 2 | Activate DDoS response team | IR Lead |
| 3 | Engage DDoS protection service | Security |
| 4 | Document attack characteristics | Analyst |
| 5 | Notify stakeholders | Communications |

### Mitigation Hierarchy

```
    DDoS MITIGATION LAYERS

    Layer 1: Upstream/ISP
    +----------------------------------+
    | BGP blackhole routing            |
    | ISP scrubbing services           |
    | Upstream rate limiting           |
    +----------------------------------+
              |
              v
    Layer 2: DDoS Protection Service
    +----------------------------------+
    | Traffic scrubbing                |
    | Geographic filtering             |
    | Rate limiting                    |
    | Challenge-response (CAPTCHA)     |
    +----------------------------------+
              |
              v
    Layer 3: CDN/Edge
    +----------------------------------+
    | Edge caching                     |
    | WAF rules                        |
    | Rate limiting                    |
    | Bot management                   |
    +----------------------------------+
              |
              v
    Layer 4: On-Premise
    +----------------------------------+
    | Firewall rules                   |
    | Load balancer config             |
    | Application hardening            |
    | Resource scaling                 |
    +----------------------------------+
```

### Mitigation Techniques by Attack Type

| Attack Type | Mitigation |
|-------------|------------|
| UDP Flood | Rate limiting, blackholing, scrubbing |
| SYN Flood | SYN cookies, rate limiting, scrubbing |
| HTTP Flood | Rate limiting, CAPTCHA, WAF rules |
| Amplification | BCP38 filtering, rate limiting |
| Slowloris | Connection timeouts, connection limits |
| DNS Flood | Rate limiting, DNSSEC, anycast |

---

## Mitigation Procedures

### Upstream Mitigation

| Action | When to Use | Implementation |
|--------|-------------|----------------|
| BGP blackhole | Severe attack, sacrifice target | Advertise /32 with blackhole community |
| Remote triggered blackhole | Selective blackholing | RTBH with ISP |
| Scrubbing center | Volume exceeds capacity | Route traffic through scrubbing |
| GRE tunnel | Clean traffic return | Configure tunnel from scrubber |

### CDN/DDoS Service Mitigation

| Action | Configuration |
|--------|---------------|
| Enable attack mode | Activate heightened protection |
| Geographic blocking | Block non-business regions |
| Rate limiting | Implement request rate limits |
| Challenge pages | Deploy JavaScript/CAPTCHA challenges |
| Bot mitigation | Enable bot detection and blocking |

### On-Premise Mitigation

| Layer | Action | Example |
|-------|--------|---------|
| Firewall | Rate limiting | Max 100 conn/sec per IP |
| Firewall | Geo-blocking | Block non-business countries |
| Load balancer | Connection limits | Max connections per backend |
| Load balancer | Health check tuning | Faster failure detection |
| Server | Kernel tuning | SYN backlog, TCP timeouts |
| Application | Caching | Increase cache TTL |

### Application Layer Mitigation

```
    APPLICATION LAYER DEFENSES

    1. Rate Limiting
       - Per IP: 100 requests/minute
       - Per session: 500 requests/minute
       - Global: Based on capacity

    2. CAPTCHA/Challenges
       - On suspicious patterns
       - Above rate thresholds
       - From suspicious sources

    3. WAF Rules
       - Block known attack patterns
       - Filter malicious payloads
       - Detect automation

    4. Caching Strategy
       - Increase cache TTL
       - Cache dynamic content
       - Edge caching

    5. Resource Management
       - Connection timeouts
       - Request timeouts
       - Queue management
```

---

## Communication Plan

### Internal Communication

| Audience | Channel | Frequency | Content |
|----------|---------|-----------|---------|
| IR Team | War room/bridge | Continuous | Technical updates |
| IT Leadership | Email/call | Every 30 min | Status summary |
| Executive | Email | Hourly | Business impact |
| Support | Chat/email | As needed | Customer talking points |

### External Communication

| Audience | When | Content |
|----------|------|---------|
| Customers | Service degradation | Status page update |
| Partners | If affected | Direct communication |
| ISP/Providers | For assistance | Technical coordination |
| Media | If newsworthy | Prepared statement |

### Status Page Updates

```
    STATUS PAGE TEMPLATE

    [TIMESTAMP] - DDoS Attack - Investigating
    We are currently investigating increased error
    rates affecting [SERVICE]. Our team is actively
    working to restore normal operations.

    [TIMESTAMP] - DDoS Attack - Identified
    We have identified a DDoS attack targeting our
    infrastructure. Mitigation measures are being
    implemented.

    [TIMESTAMP] - DDoS Attack - Mitigating
    Active mitigation is in progress. Some users
    may experience intermittent issues.

    [TIMESTAMP] - DDoS Attack - Resolved
    The attack has been mitigated and services
    are operating normally. We continue to monitor.
```

---

## Attack Analysis

### Traffic Analysis

| Metric | Analysis |
|--------|----------|
| Source IPs | Distribution, geographic, ASN |
| Destination | Target services, ports |
| Protocol | UDP, TCP, HTTP, DNS |
| Packet size | Distribution, anomalies |
| Rate | Packets/sec, requests/sec |
| Duration | Attack timeline |

### Attack Attribution

| Data Point | Source |
|------------|--------|
| Source IPs | Netflow, firewall logs |
| Attack tools | Packet signatures |
| C2 infrastructure | Threat intelligence |
| Botnet identification | IP correlation |

### Documentation

```
    DDOS INCIDENT DOCUMENTATION

    Attack Summary:
    - Start time: [TIMESTAMP]
    - End time: [TIMESTAMP]
    - Duration: [HOURS:MINUTES]
    - Peak bandwidth: [Gbps]
    - Peak PPS: [packets/sec]

    Attack Characteristics:
    - Type: [Volumetric/Protocol/Application]
    - Vectors: [UDP/SYN/HTTP/etc.]
    - Source IPs: [Count, distribution]
    - Target: [Services, IPs]

    Mitigation Actions:
    - [TIMESTAMP]: [Action taken]
    - [TIMESTAMP]: [Action taken]

    Impact:
    - Service availability: [%]
    - Customer impact: [Description]
    - Financial impact: [Estimate]

    Lessons Learned:
    - [Finding 1]
    - [Finding 2]
```

---

## Recovery Phase

### Service Restoration

| Step | Action | Verification |
|------|--------|--------------|
| 1 | Confirm attack subsided | Traffic analysis |
| 2 | Gradually remove mitigation | Monitor impact |
| 3 | Restore normal operations | Service health checks |
| 4 | Clear backlogs | Queue monitoring |
| 5 | Return to normal status | Status page update |

### Post-Attack Validation

| Check | Method |
|-------|--------|
| Service availability | Synthetic monitoring |
| Performance baseline | Response time monitoring |
| Error rates | Log analysis |
| Customer access | Geographic testing |
| Security posture | Configuration review |

---

## Prevention and Preparedness

### Infrastructure Hardening

| Layer | Hardening Measure |
|-------|-------------------|
| Network | Over-provisioned bandwidth |
| Network | Anycast architecture |
| Network | BGP flowspec capability |
| Firewall | Rate limiting configured |
| Load balancer | Connection limits |
| Application | Horizontal scaling capability |
| DNS | Multiple providers, anycast |

### DDoS Protection Services

| Service Type | Capability |
|--------------|------------|
| Always-on scrubbing | Continuous protection |
| On-demand scrubbing | Manual activation |
| CDN with DDoS | Edge protection |
| DNS protection | DNS layer defense |
| Hybrid | Combined on-prem and cloud |

### Playbook Testing

| Test Type | Frequency | Purpose |
|-----------|-----------|---------|
| Tabletop exercise | Quarterly | Process validation |
| Simulated attack | Annually | Technical validation |
| Runbook review | Monthly | Documentation accuracy |
| Contact verification | Quarterly | Communication readiness |

---

## Metrics and KPIs

| Metric | Target | Measurement |
|--------|--------|-------------|
| Time to detect | < 5 minutes | Alert timestamp |
| Time to mitigate | < 30 minutes | Mitigation activation |
| Service availability | > 99.9% | Uptime monitoring |
| Attack deflection | > 95% | Traffic analysis |

---

## References

- NIST SP 800-61 Computer Security Incident Handling Guide
- US-CERT DDoS Quick Guide
- Cloud provider DDoS documentation

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
