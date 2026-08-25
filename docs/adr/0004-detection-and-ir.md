# ADR-0004 — Enfoque de ingeniería de detección y respuesta a incidentes

- **Estado:** Aceptado · **Fecha:** 2026-08-23 · **Responsable:** Ingeniería de Seguridad

## Contexto
El Entregable 04 proporciona una cronología de la brecha totalmente embebida. Debemos
producir IOCs, detecciones, un playbook de IR, mapeo MITRE, RCA y comunicaciones
ejecutivas.

## Decisión
Priorizar detecciones situadas en la parte alta de la **Pirámide del Dolor**
(comportamientos/TTP por encima de IPs): 4 reglas Sigma (administración IAM fuera de
horario, DeleteTrail antiforense CRITICAL, SQLi en los logs de la aplicación, GetObject
masivo de S3). Cargar los IOCs en un **Threat Intel Set** de GuardDuty mediante Terraform
(preferido) con un método alternativo por AWS CLI. La IR sigue NIST 800-61
(preservar→contener→erradicar→recuperar→lecciones) con AWS CLI reversible y exacto, MITRE
ATT&CK v14 (8 técnicas), RCA con 5 Porqués + queso suizo, un informe para el CEO de ≤1
página y la ruta de notificación a la SIC de la Ley 1581 (15 días hábiles).

## Consecuencias
- (+) Reglas validadas con `pysigma` (parseo limpio, 4/4). Un *intento* de DeleteTrail genera alerta incluso cuando la SCP lo bloquea.
- (+) El Threat Intel Set está bajo control de versiones y es reproducible.
- (−) La sintaxis de agregación de Sigma (GetObject masivo) depende del backend — documentado; se traduce con `sigma convert`.
- (−) Los IOCs basados en IP (185.220.101.22) caducan rápido — reevaluar cada 90 días; las reglas de comportamiento cargan con el peso.
