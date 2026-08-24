# Compliance Matrix — CIS AWS Foundations v1.4 · ISO/IEC 27001:2022 · Ley 1581

Every row links to concrete evidence in this repository. Status: **PASS** (implemented),
**FAIL** (gap), **N/A** (out of scope for this deliverable).

| # | Control (CIS AWS 1.4) | ISO 27001:2022 | Ley 1581 | Implementation | Evidence | Status |
|---|-----------------------|----------------|----------|----------------|----------|--------|
| 1 | 1.4 No root access keys / 1.5 root MFA | A.5.16, A.8.5 | Art. 4 (seguridad) | Config rule `root-account-mfa-enabled`; no root keys created | `terraform/.../monitoring.tf` (config_rules), `iam.tf` | PASS |
| 2 | 1.8 Password policy ≥14, reuse 24, 90d | A.5.17 | Art. 4 | `aws_iam_account_password_policy` (14/90/24) | `iam.tf` | PASS |
| 3 | 1.16 No `AdministratorAccess`/wildcards in prod | A.5.15, A.8.2 | Art. 4 (acceso restringido) | Least-privilege ECS roles; scoped S3/KMS/Secrets | `iam.tf` | PASS |
| 4 | 2.1.1 S3 SSE + 2.1.5 Block Public Access | A.8.24 | Art. 4 | Account BPA + per-bucket BPA + SSE-KMS CMK | `s3.tf` | PASS |
| 5 | 2.1.2 S3 deny insecure transport (TLS) | A.8.24 | Art. 4 | Bucket policy `aws:SecureTransport=false` deny | `s3.tf` | PASS |
| 6 | 3.1 CloudTrail enabled all regions | A.8.15 | Art. 4 | Multi-region trail + mgmt + S3 data events | `monitoring.tf` | PASS |
| 7 | 3.2 CloudTrail log file validation | A.8.15 | Art. 4 | `enable_log_file_validation = true` | `monitoring.tf` | PASS |
| 8 | 3.4 CloudTrail → CloudWatch Logs | A.8.15, A.8.16 | Art. 4 | `cloud_watch_logs_group_arn` wired | `monitoring.tf` | PASS |
| 9 | 3.7 KMS CMK rotation enabled | A.8.24 | Art. 4 | `enable_key_rotation = true` (RDS/S3/ECS keys) | `kms.tf` | PASS |
| 10 | 3.8 S3 bucket-level logging | A.8.15 | Art. 4 | `aws_s3_bucket_logging` on telemetry + logs | `s3.tf` | PASS |
| 11 | 4.1 Metric filter: unauthorized API / root | A.8.16 | Art. 4 | Metric filters + alarms → SNS (root, IAM, SG, KMS, trail) | `monitoring.tf` | PASS |
| 12 | 4.3 Alarm on root usage | A.8.16 | Art. 4 | `root_login` metric filter + alarm | `monitoring.tf` | PASS |
| 13 | 5.2 No SG ingress 0.0.0.0/0 to 22 | A.8.20, A.8.22 | Art. 4 | SGs restrict admin ports; Checkov CKV_AWS_24 + CKV2_FLEETSEC_1 | `securitygroups.tf`, `checkov/` | PASS |
| 14 | 5.3 No SG ingress 0.0.0.0/0 to 3389 | A.8.20 | Art. 4 | Same; Checkov CKV_AWS_25 passes | `securitygroups.tf` | PASS |
| 15 | 5.4 Default SG restricts all traffic | A.8.20 | Art. 4 | `aws_default_security_group` (no rules) | `vpc.tf` | PASS |
| 16 | RDS: encryption + Multi-AZ + no public | A.8.24, A.8.14 | Art. 4, Art. 17 | CMK, Multi-AZ, `publicly_accessible=false`, TLS forced | `rds.tf` | PASS |
| 17 | GuardDuty enabled (threat detection) | A.5.7 (threat intel), A.8.16 | Art. 4 | Detector all-region + S3 + malware + Threat Intel Set | `monitoring.tf`, `detection/threat-intel/` | PASS |
| 18 | Security Hub FSBP + CIS 1.4 | A.5.36, A.8.16 | Art. 4 | Standards subscriptions FSBP + CIS 1.4.0 | `monitoring.tf` | PASS |
| 19 | AWS Config recorder + managed rules | A.8.9 (config mgmt) | Art. 4 | Recorder + 7 managed rules | `monitoring.tf` | PASS |
| 20 | WAFv2 on ALB (SQLi, bad inputs, rate, geo) | A.8.20, A.8.23 | Art. 4 | WAF managed rules BLOCK + rate limit + geo CO/PE/US | `waf.tf` | PASS |
| 21 | Secrets in Secrets Manager (rotation 30d) | A.8.24, A.5.17 | Art. 4 | `aws_secretsmanager_secret` + rotation | `rds.tf`, remediation V-10 | PASS |
| 22 | Immutable logs (Object Lock COMPLIANCE) | A.8.15, A.5.28 | Art. 4 | Object Lock COMPLIANCE on log/evidence bucket | `s3.tf` | PASS |
| 23 | VPC Flow Logs → S3 + CloudWatch | A.8.16, A.8.20 | Art. 4 | `aws_flow_log` ALL traffic | `vpc.tf` | PASS |
| 24 | Data masking / PII protection | A.8.11 (NEW 2022) | Art. 4 (minimización) | PII log sanitizer (V-08 remediation) | `app/src/lib/pii.js` | PASS |
| 25 | Secure coding (SDLC) | A.8.28 (NEW 2022) | — | Semgrep custom rules + SAST gate + secure `/secure` twins | `semgrep/`, `.github/workflows/` | PASS |
| 26 | Incident response process | A.5.24–5.28 | Art. 4 + SIC 15 días | IR playbook + Sigma rules + SIC notification path | `detection/playbooks/` | PASS |
| 27 | SIC breach notification (15 business days) | A.5.24 | Art. 17 | Notification path + template + timeline | `detection/playbooks/ir-playbook.md` §6 | PASS |
| 28 | Cross-region S3 replication | A.8.14 | Art. 17 | Not implemented (documented accepted risk) | `s3.tf` checkov:skip CKV_AWS_144 | N/A |

**Coverage:** 27 PASS / 0 FAIL / 1 N/A (accepted, documented). ≥ 10 controls mapped as required.

**ISO 27001:2022 "new-in-2022" controls covered:** A.5.7 (threat intel), A.8.9 (config mgmt),
A.8.11 (data masking), A.8.16 (monitoring), A.8.23 (web filtering/WAF), A.8.28 (secure coding).
