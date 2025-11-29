# Security Architecture Diagrams

Reference diagrams for enterprise security architecture patterns.

---

## Enterprise Security Architecture

### Defense in Depth Model

```mermaid
flowchart TB
    subgraph Internet
        ATK[Attacker]
        USR[Legitimate Users]
    end

    subgraph Perimeter["Perimeter Security"]
        CDN[CDN/DDoS Protection]
        WAF[Web Application Firewall]
        FW[Next-Gen Firewall]
    end

    subgraph Network["Network Security"]
        IDS[IDS/IPS]
        SEG[Network Segmentation]
        NDR[Network Detection]
    end

    subgraph Endpoint["Endpoint Security"]
        EDR[EDR/XDR]
        AV[Antimalware]
        DLP[Data Loss Prevention]
    end

    subgraph Application["Application Security"]
        AUTH[Authentication]
        AUTHZ[Authorization]
        ENC[Encryption]
    end

    subgraph Data["Data Security"]
        DBENC[Database Encryption]
        MASK[Data Masking]
        BAK[Encrypted Backups]
    end

    ATK --> CDN
    USR --> CDN
    CDN --> WAF
    WAF --> FW
    FW --> IDS
    IDS --> SEG
    SEG --> NDR
    NDR --> EDR
    EDR --> AV
    AV --> DLP
    DLP --> AUTH
    AUTH --> AUTHZ
    AUTHZ --> ENC
    ENC --> DBENC
    DBENC --> MASK
    MASK --> BAK
```

---

## Zero Trust Architecture

### Identity-Centric Security Model

```mermaid
flowchart TB
    subgraph Users["Identity Layer"]
        EMP[Employees]
        CTR[Contractors]
        SVC[Service Accounts]
    end

    subgraph Identity["Identity Provider"]
        IDP[Identity Provider]
        MFA[Multi-Factor Auth]
        SSO[Single Sign-On]
        PAM[Privileged Access]
    end

    subgraph Policy["Policy Engine"]
        PDP[Policy Decision Point]
        PEP[Policy Enforcement Point]
        RISK[Risk Engine]
    end

    subgraph Resources["Protected Resources"]
        APP[Applications]
        DATA[Data Stores]
        INFRA[Infrastructure]
        API[APIs]
    end

    subgraph Monitoring["Continuous Monitoring"]
        SIEM[SIEM]
        UEBA[User Analytics]
        TI[Threat Intel]
    end

    EMP --> IDP
    CTR --> IDP
    SVC --> IDP
    IDP --> MFA
    MFA --> SSO
    SSO --> PAM
    PAM --> PDP
    PDP --> RISK
    RISK --> PEP
    PEP --> APP
    PEP --> DATA
    PEP --> INFRA
    PEP --> API
    APP --> SIEM
    DATA --> SIEM
    INFRA --> SIEM
    API --> SIEM
    SIEM --> UEBA
    UEBA --> TI
    TI --> RISK
```

---

## Cloud Security Architecture (AWS)

### Multi-Account Security Design

```mermaid
flowchart TB
    subgraph Organization["AWS Organization"]
        subgraph Management["Management Account"]
            ORG[Organizations]
            SCP[Service Control Policies]
            BILLING[Billing]
        end

        subgraph Security["Security Account"]
            SECURITYHUB[Security Hub]
            GUARDDUTY[GuardDuty]
            CONFIG[AWS Config]
            DETECTIVE[Detective]
        end

        subgraph Log["Log Archive Account"]
            CLOUDTRAIL[CloudTrail Logs]
            VPCFLOW[VPC Flow Logs]
            S3LOGS[S3 Access Logs]
        end

        subgraph Network["Network Account"]
            TGW[Transit Gateway]
            FIREWALL[Network Firewall]
            R53[Route 53]
        end

        subgraph Workloads["Workload Accounts"]
            PROD[Production]
            STG[Staging]
            DEV[Development]
        end
    end

    ORG --> SCP
    SCP --> Security
    SCP --> Log
    SCP --> Network
    SCP --> Workloads

    SECURITYHUB --> GUARDDUTY
    GUARDDUTY --> CONFIG
    CONFIG --> DETECTIVE

    CLOUDTRAIL --> SECURITYHUB
    VPCFLOW --> SECURITYHUB

    TGW --> PROD
    TGW --> STG
    TGW --> DEV
    FIREWALL --> TGW
```

---

## SOC Architecture

### Security Operations Center Design

```mermaid
flowchart LR
    subgraph Sources["Log Sources"]
        FW[Firewalls]
        EP[Endpoints]
        SRV[Servers]
        APP[Applications]
        CLOUD[Cloud Services]
        NET[Network Devices]
    end

    subgraph Collection["Log Collection"]
        AGENT[Log Agents]
        SYSLOG[Syslog Servers]
        API[API Collectors]
    end

    subgraph Processing["Data Processing"]
        PARSE[Parser]
        ENRICH[Enrichment]
        NORM[Normalization]
    end

    subgraph Analytics["Security Analytics"]
        SIEM[SIEM Platform]
        UEBA[UEBA]
        TIP[Threat Intel Platform]
        ML[ML Detection]
    end

    subgraph Response["Incident Response"]
        SOAR[SOAR Platform]
        CASE[Case Management]
        TICKET[Ticketing]
    end

    subgraph Team["SOC Team"]
        L1[Tier 1 Analysts]
        L2[Tier 2 Analysts]
        L3[Tier 3/Hunt]
        IR[IR Team]
    end

    FW --> AGENT
    EP --> AGENT
    SRV --> SYSLOG
    APP --> API
    CLOUD --> API
    NET --> SYSLOG

    AGENT --> PARSE
    SYSLOG --> PARSE
    API --> PARSE
    PARSE --> ENRICH
    ENRICH --> NORM
    NORM --> SIEM

    SIEM --> UEBA
    SIEM --> TIP
    SIEM --> ML
    UEBA --> SOAR
    TIP --> SOAR
    ML --> SOAR

    SOAR --> CASE
    CASE --> TICKET
    TICKET --> L1
    L1 --> L2
    L2 --> L3
    L3 --> IR
```

---

## Incident Response Flow

### IR Process Diagram

```mermaid
flowchart TB
    subgraph Detection["1. Detection"]
        ALERT[Security Alert]
        HUNT[Threat Hunt Finding]
        REPORT[User Report]
    end

    subgraph Triage["2. Triage"]
        VALIDATE[Validate Alert]
        CLASSIFY[Classify Severity]
        ASSIGN[Assign Owner]
    end

    subgraph Containment["3. Containment"]
        ISOLATE[Isolate Systems]
        BLOCK[Block IOCs]
        PRESERVE[Preserve Evidence]
    end

    subgraph Eradication["4. Eradication"]
        REMOVE[Remove Malware]
        PATCH[Apply Patches]
        RESET[Reset Credentials]
    end

    subgraph Recovery["5. Recovery"]
        RESTORE[Restore Systems]
        VALIDATE2[Validate Function]
        MONITOR[Enhanced Monitoring]
    end

    subgraph PostIncident["6. Post-Incident"]
        DOCUMENT[Document Incident]
        LESSONS[Lessons Learned]
        IMPROVE[Improve Controls]
    end

    ALERT --> VALIDATE
    HUNT --> VALIDATE
    REPORT --> VALIDATE
    VALIDATE --> CLASSIFY
    CLASSIFY --> ASSIGN

    ASSIGN -->|High/Critical| ISOLATE
    ASSIGN -->|Medium/Low| REMOVE

    ISOLATE --> BLOCK
    BLOCK --> PRESERVE
    PRESERVE --> REMOVE
    REMOVE --> PATCH
    PATCH --> RESET
    RESET --> RESTORE
    RESTORE --> VALIDATE2
    VALIDATE2 --> MONITOR
    MONITOR --> DOCUMENT
    DOCUMENT --> LESSONS
    LESSONS --> IMPROVE
```

---

## Network Segmentation

### Micro-Segmentation Architecture

```mermaid
flowchart TB
    subgraph Internet
        EXT[External Users]
    end

    subgraph DMZ["DMZ Zone"]
        LB[Load Balancer]
        WAF[WAF]
        PROXY[Reverse Proxy]
    end

    subgraph Web["Web Tier"]
        WEB1[Web Server 1]
        WEB2[Web Server 2]
    end

    subgraph App["Application Tier"]
        APP1[App Server 1]
        APP2[App Server 2]
        CACHE[Cache Layer]
    end

    subgraph Data["Data Tier"]
        DB1[(Primary DB)]
        DB2[(Replica DB)]
        VAULT[Secrets Vault]
    end

    subgraph Mgmt["Management Zone"]
        JUMP[Jump Server]
        LOG[Log Server]
        MON[Monitoring]
    end

    EXT -->|443| LB
    LB --> WAF
    WAF --> PROXY
    PROXY -->|8080| WEB1
    PROXY -->|8080| WEB2

    WEB1 -->|8443| APP1
    WEB2 -->|8443| APP2
    APP1 --> CACHE
    APP2 --> CACHE

    APP1 -->|5432| DB1
    APP2 -->|5432| DB1
    DB1 -->|Replication| DB2
    APP1 -->|8200| VAULT
    APP2 -->|8200| VAULT

    JUMP -->|SSH| WEB1
    JUMP -->|SSH| APP1
    JUMP -->|SSH| DB1
    LOG -.->|Syslog| WEB1
    LOG -.->|Syslog| APP1
    MON -.->|SNMP| WEB1
```

---

## Identity and Access Management

### IAM Architecture

```mermaid
flowchart TB
    subgraph Users["User Types"]
        INT[Internal Users]
        EXT[External Users]
        PRIV[Privileged Users]
        SVC[Service Accounts]
    end

    subgraph IdP["Identity Provider"]
        AD[Active Directory]
        AZURE[Azure AD]
        OKTA[Okta/Auth0]
    end

    subgraph Auth["Authentication"]
        SAML[SAML 2.0]
        OIDC[OpenID Connect]
        MFA[MFA Service]
        CERT[Certificate Auth]
    end

    subgraph Access["Access Control"]
        RBAC[Role-Based AC]
        ABAC[Attribute-Based AC]
        JIT[Just-In-Time Access]
        PAM[Privileged Access Mgmt]
    end

    subgraph Resources["Resources"]
        APPS[Applications]
        CLOUD[Cloud Resources]
        SERVERS[Servers]
        DB[Databases]
    end

    INT --> AD
    EXT --> OKTA
    PRIV --> AZURE
    SVC --> CERT

    AD --> SAML
    AZURE --> OIDC
    OKTA --> OIDC
    SAML --> MFA
    OIDC --> MFA
    CERT --> RBAC

    MFA --> RBAC
    RBAC --> ABAC
    PRIV --> PAM
    PAM --> JIT

    ABAC --> APPS
    ABAC --> CLOUD
    JIT --> SERVERS
    JIT --> DB
```

---

## Data Flow Security

### Secure Data Pipeline

```mermaid
flowchart LR
    subgraph Ingestion["Data Ingestion"]
        SRC[Data Sources]
        VAL[Validation]
        CLASS[Classification]
    end

    subgraph Processing["Data Processing"]
        ENC[Encryption]
        MASK[Masking/Tokenization]
        TRANS[Transformation]
    end

    subgraph Storage["Secure Storage"]
        HOT[(Hot Storage)]
        WARM[(Warm Storage)]
        COLD[(Cold/Archive)]
    end

    subgraph Access["Data Access"]
        API[Secure APIs]
        QUERY[Query Engine]
        EXPORT[Export Controls]
    end

    subgraph Governance["Data Governance"]
        CATALOG[Data Catalog]
        LINEAGE[Data Lineage]
        AUDIT[Audit Logs]
    end

    SRC --> VAL
    VAL --> CLASS
    CLASS --> ENC
    ENC --> MASK
    MASK --> TRANS
    TRANS --> HOT
    HOT --> WARM
    WARM --> COLD

    HOT --> API
    API --> QUERY
    QUERY --> EXPORT

    CLASS --> CATALOG
    TRANS --> LINEAGE
    API --> AUDIT
```

---

## Threat Detection Architecture

### Multi-Layer Detection

```mermaid
flowchart TB
    subgraph Perimeter["Perimeter Detection"]
        WAFLOG[WAF Logs]
        FWLOG[Firewall Logs]
        DNSLOG[DNS Logs]
    end

    subgraph Network["Network Detection"]
        NETFLOW[NetFlow/IPFIX]
        PCAP[Packet Capture]
        NDR[NDR Platform]
    end

    subgraph Endpoint["Endpoint Detection"]
        EDRTEL[EDR Telemetry]
        SYSMON[Sysmon Events]
        PROCMON[Process Monitoring]
    end

    subgraph Cloud["Cloud Detection"]
        CLOUDTRAIL[CloudTrail]
        AZURELOG[Azure Activity]
        GCPLOG[GCP Audit]
    end

    subgraph Analytics["Detection Analytics"]
        RULES[Detection Rules]
        ML[ML Models]
        BEHAV[Behavioral Analysis]
        TI[Threat Intel Matching]
    end

    subgraph Output["Detection Output"]
        ALERTS[Security Alerts]
        INCIDENTS[Incidents]
        HUNTS[Hunt Leads]
    end

    WAFLOG --> RULES
    FWLOG --> RULES
    DNSLOG --> TI
    NETFLOW --> BEHAV
    PCAP --> NDR
    NDR --> ML
    EDRTEL --> RULES
    SYSMON --> BEHAV
    PROCMON --> ML
    CLOUDTRAIL --> RULES
    AZURELOG --> TI
    GCPLOG --> TI

    RULES --> ALERTS
    ML --> ALERTS
    BEHAV --> INCIDENTS
    TI --> HUNTS
```

---

## DevSecOps Pipeline

### Secure CI/CD Architecture

```mermaid
flowchart LR
    subgraph Dev["Development"]
        CODE[Code Commit]
        PRESCAN[Pre-commit Hooks]
    end

    subgraph Build["Build Phase"]
        SAST[SAST Scan]
        SCA[Dependency Scan]
        SECRETS[Secret Detection]
        LINT[Security Linting]
    end

    subgraph Test["Test Phase"]
        DAST[DAST Scan]
        IAST[IAST Testing]
        PENTEST[Security Testing]
        FUZZ[Fuzzing]
    end

    subgraph Deploy["Deploy Phase"]
        IMGSCAN[Container Scan]
        IACSCAN[IaC Scan]
        POLICY[Policy Check]
        SIGN[Image Signing]
    end

    subgraph Runtime["Runtime"]
        RASP[RASP]
        CWPP[CWPP]
        CSPM[CSPM]
    end

    CODE --> PRESCAN
    PRESCAN --> SAST
    SAST --> SCA
    SCA --> SECRETS
    SECRETS --> LINT
    LINT --> DAST
    DAST --> IAST
    IAST --> PENTEST
    PENTEST --> FUZZ
    FUZZ --> IMGSCAN
    IMGSCAN --> IACSCAN
    IACSCAN --> POLICY
    POLICY --> SIGN
    SIGN --> RASP
    RASP --> CWPP
    CWPP --> CSPM
```

---

## Backup and Recovery Architecture

### Disaster Recovery Design

```mermaid
flowchart TB
    subgraph Primary["Primary Region"]
        PROD1[Production Systems]
        DB1[(Primary Database)]
        STORE1[Storage]
    end

    subgraph Secondary["DR Region"]
        PROD2[Standby Systems]
        DB2[(Replica Database)]
        STORE2[Replicated Storage]
    end

    subgraph Backup["Backup Infrastructure"]
        SNAP[Snapshots]
        BACKUP[Backup Vault]
        ARCHIVE[Cold Archive]
    end

    subgraph Recovery["Recovery Process"]
        DETECT[Failure Detection]
        FAILOVER[Automated Failover]
        VALIDATE[Validation]
        DNS[DNS Switch]
    end

    PROD1 -->|Sync Replication| PROD2
    DB1 -->|Async Replication| DB2
    STORE1 -->|Cross-Region Copy| STORE2

    PROD1 --> SNAP
    DB1 --> SNAP
    SNAP --> BACKUP
    BACKUP --> ARCHIVE

    DETECT --> FAILOVER
    FAILOVER --> VALIDATE
    VALIDATE --> DNS
    DNS --> PROD2
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
