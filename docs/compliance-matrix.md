# Matriz de Cumplimiento — CIS AWS Foundations v1.4 · ISO/IEC 27001:2022 · Ley 1581

Cada fila enlaza con evidencia concreta en este repositorio. Estado: **PASS** (implementado),
**FAIL** (brecha), **N/A** (fuera del alcance de este entregable).

| # | Control (CIS AWS 1.4) | ISO 27001:2022 | Ley 1581 | Implementación | Evidencia | Estado |
|---|-----------------------|----------------|----------|----------------|----------|--------|
| 1 | 1.4 Sin claves de acceso root / 1.5 MFA en root | A.5.16, A.8.5 | Art. 4 (seguridad) | Regla de Config `root-account-mfa-enabled`; no se crean claves de root | `terraform/.../monitoring.tf` (config_rules), `iam.tf` | PASS |
| 2 | 1.8 Política de contraseñas ≥14, reutilización 24, 90d | A.5.17 | Art. 4 | `aws_iam_account_password_policy` (14/90/24) | `iam.tf` | PASS |
| 3 | 1.16 Sin `AdministratorAccess`/comodines en producción | A.5.15, A.8.2 | Art. 4 (acceso restringido) | Roles ECS de mínimo privilegio; S3/KMS/Secrets acotados | `iam.tf` | PASS |
| 4 | 2.1.1 SSE de S3 + 2.1.5 Block Public Access | A.8.24 | Art. 4 | BPA de cuenta + BPA por bucket + SSE-KMS CMK | `s3.tf` | PASS |
| 5 | 2.1.2 S3 deniega transporte inseguro (TLS) | A.8.24 | Art. 4 | Bucket policy que deniega `aws:SecureTransport=false` | `s3.tf` | PASS |
| 6 | 3.1 CloudTrail habilitado en todas las regiones | A.8.15 | Art. 4 | Trail multirregión + eventos de gestión + eventos de datos de S3 | `monitoring.tf` | PASS |
| 7 | 3.2 Validación de archivos de log de CloudTrail | A.8.15 | Art. 4 | `enable_log_file_validation = true` | `monitoring.tf` | PASS |
| 8 | 3.4 CloudTrail → CloudWatch Logs | A.8.15, A.8.16 | Art. 4 | `cloud_watch_logs_group_arn` conectado | `monitoring.tf` | PASS |
| 9 | 3.7 Rotación de CMK de KMS habilitada | A.8.24 | Art. 4 | `enable_key_rotation = true` (claves RDS/S3/ECS) | `kms.tf` | PASS |
| 10 | 3.8 Logging a nivel de bucket S3 | A.8.15 | Art. 4 | `aws_s3_bucket_logging` en telemetría + logs | `s3.tf` | PASS |
| 11 | 4.1 Filtro de métrica: API no autorizada / root | A.8.16 | Art. 4 | Filtros de métrica + alarmas → SNS (root, IAM, SG, KMS, trail) | `monitoring.tf` | PASS |
| 12 | 4.3 Alarma ante uso de root | A.8.16 | Art. 4 | Filtro de métrica `root_login` + alarma | `monitoring.tf` | PASS |
| 13 | 5.2 Sin ingreso de SG 0.0.0.0/0 al 22 | A.8.20, A.8.22 | Art. 4 | Los SG restringen los puertos de administración; Checkov CKV_AWS_24 + CKV2_FLEETSEC_1 | `securitygroups.tf`, `checkov/` | PASS |
| 14 | 5.3 Sin ingreso de SG 0.0.0.0/0 al 3389 | A.8.20 | Art. 4 | Igual; Checkov CKV_AWS_25 aprueba | `securitygroups.tf` | PASS |
| 15 | 5.4 El SG por defecto restringe todo el tráfico | A.8.20 | Art. 4 | `aws_default_security_group` (sin reglas) | `vpc.tf` | PASS |
| 16 | RDS: cifrado + Multi-AZ + sin acceso público | A.8.24, A.8.14 | Art. 4, Art. 17 | CMK, Multi-AZ, `publicly_accessible=false`, TLS forzado | `rds.tf` | PASS |
| 17 | GuardDuty habilitado (detección de amenazas) | A.5.7 (inteligencia de amenazas), A.8.16 | Art. 4 | Detector en todas las regiones + S3 + malware + Threat Intel Set | `monitoring.tf`, `detection/threat-intel/` | PASS |
| 18 | Security Hub FSBP + CIS 1.4 | A.5.36, A.8.16 | Art. 4 | Suscripciones a estándares FSBP + CIS 1.4.0 | `monitoring.tf` | PASS |
| 19 | Grabador de AWS Config + reglas gestionadas | A.8.9 (gestión de configuración) | Art. 4 | Grabador + 7 reglas gestionadas | `monitoring.tf` | PASS |
| 20 | WAFv2 en ALB (SQLi, bad inputs, rate, geo) | A.8.20, A.8.23 | Art. 4 | Reglas gestionadas de WAF en BLOCK + rate limit + geo CO/PE/US | `waf.tf` | PASS |
| 21 | Secretos en Secrets Manager (rotación 30d) | A.8.24, A.5.17 | Art. 4 | `aws_secretsmanager_secret` + rotación | `rds.tf`, remediación V-10 | PASS |
| 22 | Logs inmutables (Object Lock COMPLIANCE) | A.8.15, A.5.28 | Art. 4 | Object Lock COMPLIANCE en el bucket de logs/evidencia | `s3.tf` | PASS |
| 23 | VPC Flow Logs → S3 + CloudWatch | A.8.16, A.8.20 | Art. 4 | `aws_flow_log` para TODO el tráfico | `vpc.tf` | PASS |
| 24 | Enmascaramiento de datos / protección de PII | A.8.11 (NUEVO 2022) | Art. 4 (minimización) | Sanitizador de PII en logs (remediación V-08) | `app/src/lib/pii.js` | PASS |
| 25 | Codificación segura (SDLC) | A.8.28 (NUEVO 2022) | — | Reglas personalizadas de Semgrep + puerta SAST + gemelos seguros `/secure` | `semgrep/`, `.github/workflows/` | PASS |
| 26 | Proceso de respuesta a incidentes | A.5.24–5.28 | Art. 4 + SIC 15 días | Playbook de IR + reglas Sigma + ruta de notificación a la SIC | `detection/playbooks/` | PASS |
| 27 | Notificación de brecha a la SIC (15 días hábiles) | A.5.24 | Art. 17 | Ruta de notificación + plantilla + cronología | `detection/playbooks/ir-playbook.md` §6 | PASS |
| 28 | Replicación de S3 entre regiones | A.8.14 | Art. 17 | No implementado (riesgo aceptado documentado) | `s3.tf` checkov:skip CKV_AWS_144 | N/A |

**Cobertura:** 27 PASS / 0 FAIL / 1 N/A (aceptado, documentado). ≥ 10 controles mapeados según lo exigido.

**Controles ISO 27001:2022 «nuevos en 2022» cubiertos:** A.5.7 (inteligencia de amenazas), A.8.9 (gestión de configuración),
A.8.11 (enmascaramiento de datos), A.8.16 (monitoreo), A.8.23 (filtrado web/WAF), A.8.28 (codificación segura).
