# Kubernetes Security Checklist

Comprehensive checklist for securing Kubernetes clusters and workloads.

---

## Cluster Configuration

### API Server

- [ ] API server not exposed to internet
- [ ] Anonymous authentication disabled
- [ ] RBAC enabled
- [ ] Audit logging enabled
- [ ] Admission controllers configured
- [ ] API server bound to internal interface
- [ ] Insecure port disabled (--insecure-port=0)

### etcd

- [ ] etcd encrypted at rest
- [ ] etcd accessible only from API server
- [ ] TLS enabled for etcd communication
- [ ] etcd authentication enabled
- [ ] Regular etcd backups

### Kubelet

- [ ] Anonymous authentication disabled
- [ ] Authorization mode set to Webhook
- [ ] Read-only port disabled
- [ ] TLS certificates configured
- [ ] Protect kernel defaults enabled

---

## Authentication and Authorization

### Authentication

- [ ] Service account tokens rotated
- [ ] OIDC authentication configured
- [ ] No static tokens or basic auth
- [ ] Certificate-based auth properly managed
- [ ] Service account auto-mounting disabled by default

### RBAC

- [ ] Cluster-admin role restricted
- [ ] Least privilege for service accounts
- [ ] No wildcard permissions
- [ ] RoleBindings preferred over ClusterRoleBindings
- [ ] Regular RBAC audits
- [ ] Default service accounts restricted

---

## Network Security

### Network Policies

- [ ] Default deny network policy
- [ ] Namespace isolation
- [ ] Pod-to-pod restrictions
- [ ] Egress restrictions
- [ ] Ingress restrictions
- [ ] Network policy coverage complete

### Ingress

- [ ] TLS termination configured
- [ ] WAF integrated (if applicable)
- [ ] Rate limiting configured
- [ ] Authentication at ingress
- [ ] Ingress class specified

### Service Mesh

- [ ] mTLS between services
- [ ] Service-to-service authorization
- [ ] Traffic encryption
- [ ] Access logging

---

## Pod Security

### Pod Security Standards

- [ ] Privileged containers prohibited
- [ ] Root containers prohibited
- [ ] Host namespace sharing prohibited
- [ ] Host path mounts restricted
- [ ] Capabilities dropped
- [ ] Read-only root filesystem
- [ ] Seccomp profiles applied
- [ ] AppArmor/SELinux enabled

### Security Context

```yaml
# Recommended Security Context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

### Resource Limits

- [ ] CPU limits set
- [ ] Memory limits set
- [ ] Resource quotas per namespace
- [ ] Limit ranges configured
- [ ] PodDisruptionBudgets defined

---

## Container Images

### Image Security

- [ ] Images from trusted registries only
- [ ] Image scanning in CI/CD
- [ ] No latest tag in production
- [ ] Image signing/verification
- [ ] Base images regularly updated
- [ ] Minimal base images (distroless/alpine)
- [ ] No secrets in images

### Registry Security

- [ ] Private registry used
- [ ] Registry authentication required
- [ ] Image pull secrets managed
- [ ] Registry scanning enabled

---

## Secrets Management

### Native Secrets

- [ ] Secrets not stored in ConfigMaps
- [ ] Secrets encrypted at rest (etcd)
- [ ] Secrets mounted as files (not env vars)
- [ ] Service account tokens minimal scope
- [ ] Regular secret rotation

### External Secrets

- [ ] External secrets manager integration
- [ ] Vault or equivalent configured
- [ ] Secret injection at runtime
- [ ] Secrets not in version control

---

## Monitoring and Logging

### Audit Logging

- [ ] Kubernetes audit logging enabled
- [ ] Audit policy defined
- [ ] Audit logs shipped to SIEM
- [ ] Metadata and request/response logged
- [ ] Log retention appropriate

### Container Logging

- [ ] Application logs collected
- [ ] Centralized log aggregation
- [ ] Log integrity protected
- [ ] Sensitive data not logged

### Monitoring

- [ ] Cluster metrics collected
- [ ] Pod metrics collected
- [ ] Alerting configured
- [ ] Dashboard for visibility
- [ ] Anomaly detection

---

## Compliance and Governance

### Policy Enforcement

- [ ] OPA/Gatekeeper deployed
- [ ] Admission policies defined
- [ ] Policy violations blocked/alerted
- [ ] Policies version controlled

### Compliance Scanning

- [ ] CIS Kubernetes benchmark
- [ ] Regular compliance scans
- [ ] Remediation tracking
- [ ] Drift detection

---

## Disaster Recovery

### Backup

- [ ] etcd backups automated
- [ ] Backup encryption
- [ ] Backup testing
- [ ] Off-cluster backup storage
- [ ] Application data backed up

### Recovery

- [ ] Recovery procedures documented
- [ ] Recovery testing performed
- [ ] RTO/RPO defined
- [ ] Multi-cluster architecture (if required)

---

## Supply Chain Security

### Build Pipeline

- [ ] Signed commits
- [ ] Reviewed PRs
- [ ] Automated security testing
- [ ] SBOM generation
- [ ] Provenance attestation

### Deployment Pipeline

- [ ] GitOps workflow
- [ ] Deployment approval process
- [ ] Rollback procedures
- [ ] Canary/blue-green deployments

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | Security Architecture | Initial release |
