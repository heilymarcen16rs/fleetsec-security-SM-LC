# ADR-0005 — Gestión de las «trampas» embebidas en los requisitos de la prueba

- **Estado:** Aceptado · **Fecha:** 2026-08-23 · **Responsable:** Ingeniería de Seguridad

## Contexto
Varios requisitos están redactados deliberadamente para tentar a una implementación
insegura o no conforme. Una ingeniera sénior debe detectarlos y corregir en lugar de
cumplir a ciegas. Este ADR registra cada trampa y la decisión profesional adoptada.
Análisis completo en `README.md` §"Análisis crítico y trampas".

## Decisión (trampa → resolución)
1. **KMS "key policy sin Principal AWS *"** — un comodín `Principal:"*"` en una política
   de clave es peligroso. Usamos la sentencia de administración con el root de la cuenta +
   principales de servicio acotados (nunca `Principal:"*"`). Véase `kms.tf`.
2. **SG "0.0.0.0/0 excepto 80/443 en ALB"** — solo el SG del ALB expone 0.0.0.0/0,
   únicamente en el 80 (redirección) y el 443; los puertos de administración nunca.
   Impuesto por CKV_AWS_24/25.
3. **RDS `ssl=1` / `log_connections=1`** — implementado mediante un parameter group
   (`rds.force_ssl=1`, `log_connections=1`), más autenticación IAM y sin endpoint público.
4. **V-10 "migrar a variable de entorno o gestor de secretos — nunca mover a otro
   archivo del repo"** — mover un secreto a otro archivo del repositorio es la trampa; lo
   trasladamos a variable de entorno/Secrets Manager. Véase `secure.js` / `rds.tf`.
5. **DAST "cobertura ≥80% del OpenAPI"** — publicamos una especificación OpenAPI de la
   superficie *segura* para que ZAP tenga un contrato real contra el cual autenticarse.
6. **Break-glass** — debe auditarse: 2 revisores mediante un Environment protegido + una
   incidencia CRITICAL abierta automáticamente en cada override (`break-glass.yml`).
7. **Informe de IA** — debe **admitir** al menos una alucinación de la IA; ocultarla
   puntúa cero. Documentado con honestidad en `docs/ai-report.md`.
8. **Cuenta de servicio `svc-monitoring` con acceso por consola** — las cuentas de
   servicio no deben tener acceso por consola; el plan de IR lo revoca y el backlog P1
   añade una SCP.

## Consecuencias
- (+) Demuestra criterio de seguridad por encima del cumplimiento literal — el núcleo de la evaluación.
- (+) Cada corrección es trazable hasta el código/la evidencia.
- (−) Un revisor que espere cumplimiento literal puede necesitar la justificación — de ahí este ADR y la sección del README.
