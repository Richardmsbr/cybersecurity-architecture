# Reconnaissance Techniques

## Overview

Reconnaissance is the first phase of penetration testing, involving gathering information about the target.

---

## Passive Reconnaissance

### OSINT Sources

| Source | Information | Tools |
|--------|-------------|-------|
| WHOIS | Domain registration | whois, amass |
| DNS | Subdomains, records | dig, dnsrecon |
| Certificate Transparency | Certificates | crt.sh, certspotter |
| Search Engines | Indexed pages | Google dorks, Shodan |
| Social Media | Employee info | LinkedIn, Twitter |
| Job Postings | Technology stack | Indeed, LinkedIn |
| Code Repositories | Source code leaks | GitHub, GitLab |

### Google Dorks

```
# Find login pages
site:target.com inurl:login OR inurl:admin OR inurl:signin

# Find exposed files
site:target.com filetype:pdf OR filetype:doc OR filetype:xls

# Find configuration files
site:target.com filetype:env OR filetype:config OR filetype:yml

# Find backup files
site:target.com filetype:bak OR filetype:backup OR filetype:old

# Find error messages
site:target.com "error" OR "warning" OR "exception"
```

### Subdomain Enumeration

```bash
# Amass
amass enum -d target.com -o subdomains.txt

# Subfinder
subfinder -d target.com -o subdomains.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# DNS brute force
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt
```

---

## Active Reconnaissance

### Port Scanning

```bash
# Nmap - Full scan
nmap -sS -sV -sC -p- -oA full_scan target.com

# Nmap - Quick scan
nmap -sS --top-ports 1000 target.com

# Masscan - Fast scan
masscan -p1-65535 target.com --rate=1000

# Rustscan - Very fast
rustscan -a target.com -- -sV -sC
```

### Web Enumeration

```bash
# Directory bruteforce
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/big.txt

# Technology detection
whatweb https://target.com
wappalyzer-cli https://target.com

# Virtual host discovery
ffuf -w vhosts.txt -u https://target.com -H "Host: FUZZ.target.com"

# API endpoint discovery
ffuf -w api-endpoints.txt -u https://target.com/api/FUZZ
```

---

## Information Gathering Checklist

```
PASSIVE:
□ WHOIS lookup
□ DNS records (A, MX, NS, TXT, CNAME)
□ Subdomain enumeration
□ Certificate transparency search
□ Google dorking
□ Shodan/Censys search
□ LinkedIn employee enumeration
□ GitHub/GitLab code search
□ Wayback Machine archive
□ Job posting analysis

ACTIVE:
□ Port scanning
□ Service enumeration
□ Web technology detection
□ Directory brute forcing
□ Virtual host discovery
□ SSL/TLS analysis
□ WAF detection
□ CMS identification
□ API endpoint discovery
```

---

## Tools Reference

| Tool | Purpose | Command |
|------|---------|---------|
| Amass | Subdomain enum | `amass enum -d target.com` |
| Nmap | Port scanning | `nmap -sV target.com` |
| Gobuster | Directory brute | `gobuster dir -u URL -w wordlist` |
| ffuf | Web fuzzing | `ffuf -u URL/FUZZ -w wordlist` |
| Nuclei | Vuln scanning | `nuclei -u URL` |
| httpx | HTTP probing | `httpx -l hosts.txt` |
