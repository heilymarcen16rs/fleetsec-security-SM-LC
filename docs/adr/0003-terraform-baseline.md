# ADR-0003 — Línea base de seguridad de Terraform y excepciones de Checkov documentadas

- **Estado:** Aceptado · **Fecha:** 2026-08-23 · **Responsable:** Ingeniería de Seguridad / Plataforma Cloud

## Contexto
El Entregable 03 pide un módulo `modules/security-baseline` que modele una base segura de
AWS, con `terraform validate` limpio y un análisis de Checkov. Algunos ajustes solicitados
son en realidad **trampas** (véase ADR-0005) y algunos controles de Checkov quedan fuera
del alcance de una línea base de red/datos (p. ej., los recursos ALB/ECS residen en el
stack de la aplicación).

## Decisión
Escribir un módulo autocontenido (VPC de 3 capas, CMK de KMS, S3 + Object Lock, RDS
Multi-AZ, Secrets Manager, CloudTrail, Config, GuardDuty, Security Hub, WAFv2) cuyos SG
son consumidos por el stack de la aplicación mediante outputs. Llevar Checkov a **0
fallidos** corrigiendo cada brecha real de bajo costo (bloqueo del SG por defecto, logging
de accesos, autenticación IAM/PI/monitoreo mejorado en RDS, ciclo de vida, SNS de
CloudTrail, logging de WAF) y añadiendo **12 skips documentados en línea**
(`checkov:skip=ID:reason`) para elementos intencionales/fuera de alcance (p. ej., la
redirección del puerto 80 del ALB por requerimiento, la replicación entre regiones como
riesgo aceptado, la política de la clave raíz de KMS). Añadir una barrera de protección
personalizada (CKV2_FLEETSEC_1 en YAML + Python con pruebas unitarias).

## Consecuencias
- (+) El resultado de `checkov` es de calidad de auditoría: 251 aprobados / 0 fallidos / 12 skips documentados.
- (+) La trampa del puerto de administración se impone mediante controles integrados (CKV_AWS_24/25) que APRUEBAN nuestros SG y RECHAZAN un SG defectuoso.
- (−) `terraform validate`/`plan` completos deben ejecutarse localmente (sin credenciales cloud en CI); la sintaxis HCL se validó offline para los 12 archivos.
- (−) El artefacto draw.io se genera a partir del código Mermaid proporcionado.
