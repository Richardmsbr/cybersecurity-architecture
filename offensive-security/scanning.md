# Scanning and Enumeration

Scanning and enumeration are critical phases in penetration testing that involve active probing of target systems to identify services, vulnerabilities, and potential attack vectors.

---

## Scanning Phases

```
    SCANNING METHODOLOGY

    1. HOST DISCOVERY
    +----------------------------------+
    | Identify live hosts              |
    | ICMP, TCP, UDP probes            |
    +----------------------------------+
              |
              v
    2. PORT SCANNING
    +----------------------------------+
    | Identify open ports              |
    | TCP/UDP services                 |
    +----------------------------------+
              |
              v
    3. SERVICE ENUMERATION
    +----------------------------------+
    | Identify service versions        |
    | Banner grabbing                  |
    +----------------------------------+
              |
              v
    4. OS FINGERPRINTING
    +----------------------------------+
    | Identify operating system        |
    | Version detection                |
    +----------------------------------+
              |
              v
    5. VULNERABILITY SCANNING
    +----------------------------------+
    | Identify known vulnerabilities   |
    | CVE mapping                      |
    +----------------------------------+
```

---

## Host Discovery

### Discovery Techniques

| Technique | Method | Stealth Level |
|-----------|--------|---------------|
| ICMP Echo | Ping sweep | Low |
| TCP SYN | SYN to common ports | Medium |
| TCP ACK | ACK probe | Medium |
| UDP | UDP probe | Medium |
| ARP | Local network only | High |

### Discovery Commands

```bash
# ICMP Ping Sweep
nmap -sn 192.168.1.0/24

# TCP SYN Discovery
nmap -sn -PS22,80,443 192.168.1.0/24

# ARP Discovery (local network)
nmap -sn -PR 192.168.1.0/24

# Combined Discovery
nmap -sn -PE -PP -PS80,443 -PA3389 192.168.1.0/24

# Masscan (fast discovery)
masscan 192.168.1.0/24 -p80,443 --rate=1000
```

---

## Port Scanning

### Scan Types

| Type | Description | Use Case |
|------|-------------|----------|
| TCP SYN | Half-open scan | Default, stealthy |
| TCP Connect | Full connection | When SYN fails |
| UDP | UDP services | DNS, SNMP, NTP |
| FIN/NULL/Xmas | Stealth scans | Firewall evasion |
| ACK | Firewall mapping | Rule detection |

### Port Scanning Commands

```bash
# TCP SYN Scan (default)
nmap -sS 192.168.1.1

# Full TCP Connect
nmap -sT 192.168.1.1

# UDP Scan
nmap -sU 192.168.1.1

# All ports
nmap -p- 192.168.1.1

# Top 1000 ports
nmap --top-ports 1000 192.168.1.1

# Specific ports
nmap -p22,80,443,8080 192.168.1.1

# Service version detection
nmap -sV 192.168.1.1

# Aggressive scan
nmap -A 192.168.1.1
```

### Common Ports

| Port | Service | Notes |
|------|---------|-------|
| 21 | FTP | File transfer, anonymous access |
| 22 | SSH | Remote access, brute force |
| 23 | Telnet | Clear text, legacy |
| 25 | SMTP | Mail, relay testing |
| 53 | DNS | Zone transfer, tunneling |
| 80 | HTTP | Web services |
| 110 | POP3 | Mail retrieval |
| 139/445 | SMB | File sharing, EternalBlue |
| 143 | IMAP | Mail access |
| 443 | HTTPS | Encrypted web |
| 1433 | MSSQL | Database |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote desktop |
| 5432 | PostgreSQL | Database |
| 5900 | VNC | Remote desktop |
| 8080 | HTTP-Alt | Web proxy/alt |

---

## Service Enumeration

### Banner Grabbing

```bash
# Netcat banner grab
nc -nv 192.168.1.1 22

# Nmap banner scripts
nmap -sV --script=banner 192.168.1.1

# HTTP headers
curl -I http://192.168.1.1

# SSL/TLS information
openssl s_client -connect 192.168.1.1:443
```

### Service-Specific Enumeration

```
    SERVICE ENUMERATION TARGETS

    SMB (139/445):
    - Share enumeration
    - User enumeration
    - Version detection
    - Vulnerability check

    HTTP/HTTPS (80/443):
    - Directory enumeration
    - Technology detection
    - Virtual hosts
    - SSL/TLS analysis

    DNS (53):
    - Zone transfer
    - Subdomain enumeration
    - Record enumeration

    SMTP (25):
    - User enumeration (VRFY)
    - Relay testing
    - Version detection

    SNMP (161):
    - Community strings
    - System information
    - Network configuration
```

### SMB Enumeration

```bash
# Share enumeration
smbclient -L //192.168.1.1 -N
smbmap -H 192.168.1.1

# User enumeration
enum4linux -a 192.168.1.1
rpcclient -U "" -N 192.168.1.1

# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users 192.168.1.1
nmap --script smb-vuln* 192.168.1.1
```

### DNS Enumeration

```bash
# Zone transfer
dig axfr @ns1.target.com target.com
host -l target.com ns1.target.com

# DNS records
dig ANY target.com
dig MX target.com
dig TXT target.com

# Subdomain enumeration
dnsenum target.com
subfinder -d target.com
amass enum -d target.com
```

### Web Enumeration

```bash
# Directory bruteforce
gobuster dir -u http://target.com -w /wordlists/common.txt
feroxbuster -u http://target.com -w /wordlists/common.txt
dirsearch -u http://target.com

# Technology detection
whatweb http://target.com
wappalyzer http://target.com

# Virtual host discovery
gobuster vhost -u http://target.com -w /wordlists/vhosts.txt

# SSL/TLS analysis
sslscan target.com
testssl.sh target.com
```

---

## OS Fingerprinting

### Active Fingerprinting

```bash
# Nmap OS detection
nmap -O 192.168.1.1
nmap -O --osscan-guess 192.168.1.1

# Combined with version
nmap -O -sV 192.168.1.1
```

### Passive Fingerprinting

| Indicator | Detection Method |
|-----------|------------------|
| TTL Values | Packet capture |
| TCP Window Size | Network analysis |
| TCP Options | SYN packet analysis |
| Service Banners | Banner grabbing |

---

## Vulnerability Scanning

### Automated Scanners

| Tool | Type | Use Case |
|------|------|----------|
| Nessus | Commercial | Enterprise scanning |
| OpenVAS | Open Source | General scanning |
| Nuclei | Open Source | Template-based |
| Nikto | Open Source | Web server |
| WPScan | Open Source | WordPress |
| SQLMap | Open Source | SQL injection |

### Nmap Vulnerability Scripts

```bash
# All vulnerability scripts
nmap --script vuln 192.168.1.1

# Specific vulnerability
nmap --script smb-vuln-ms17-010 192.168.1.1
nmap --script http-vuln* 192.168.1.1

# Safe scripts only
nmap --script "safe and vuln" 192.168.1.1
```

### Web Vulnerability Scanning

```bash
# Nikto web scan
nikto -h http://target.com

# Nuclei templates
nuclei -u http://target.com -t cves/
nuclei -u http://target.com -t vulnerabilities/

# OWASP ZAP
zap-cli quick-scan http://target.com
```

---

## Evasion Techniques

### Scan Optimization

| Technique | Purpose | Command |
|-----------|---------|---------|
| Timing | Slow scan | -T0 to -T5 |
| Fragmentation | IDS evasion | -f |
| Decoys | Source obfuscation | -D decoy1,decoy2 |
| Source Port | Firewall bypass | --source-port 53 |
| MTU | Fragment size | --mtu 24 |

### Evasion Commands

```bash
# Slow scan
nmap -T0 192.168.1.1

# Fragmentation
nmap -f 192.168.1.1

# Decoys
nmap -D RND:10 192.168.1.1

# Source port spoofing
nmap --source-port 53 192.168.1.1

# Combined evasion
nmap -T2 -f --source-port 53 -D RND:5 192.168.1.1
```

---

## Documentation

### Scan Documentation Template

```
SCANNING REPORT

Target: [IP/Range]
Date: [Date]
Tester: [Name]

METHODOLOGY:
1. Host discovery
2. Port scanning
3. Service enumeration
4. Vulnerability scanning

FINDINGS:

Host: 192.168.1.1
OS: [Detected OS]

Open Ports:
| Port | State | Service | Version |
|------|-------|---------|---------|
| 22   | open  | SSH     | OpenSSH 7.4 |
| 80   | open  | HTTP    | Apache 2.4.6 |
| 443  | open  | HTTPS   | Apache 2.4.6 |

Vulnerabilities:
| CVE | Severity | Service | Description |
|-----|----------|---------|-------------|
| ... | ...      | ...     | ...         |

RECOMMENDATIONS:
[Remediation steps]
```

---

## References

- Nmap Network Scanning (Official Guide)
- PTES Technical Guidelines
- OWASP Testing Guide

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
