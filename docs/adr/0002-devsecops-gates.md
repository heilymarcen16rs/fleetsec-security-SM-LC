# ADR-0002 — Puertas de calidad y umbrales de DevSecOps

- **Estado:** Aceptado · **Fecha:** 2026-08-23 · **Responsable:** Ingeniería de Seguridad

## Contexto
El pipeline debe imponer puertas estrictas (SAST, SCA, DAST, contenedor, IaC, secretos),
pero el repositorio contiene de forma intencionada un laboratorio vulnerable. Una puerta
ingenua de «0 hallazgos» fallaría de forma permanente o nos obligaría a eliminar el
material didáctico.

## Decisión
SAST de dos niveles: una ejecución **informativa** de Semgrep sobre todo el repositorio
(muestra las reglas personalizadas activándose, no bloqueante) más una puerta
**bloqueante** solo sobre el código de producción (`app/src`, excluyendo `vulnerable.js`
y las pruebas), con supresiones `nosemgrep` en línea que incluyen `razón · fecha ·
responsable` para el secreto de laboratorio V-10.
Umbrales: SCA bloquea HIGH/CRITICAL (≈ CVSS ≥8 directo / ≥9 indirecto), el contenedor
bloquea CRITICAL, DAST bloquea HIGH/CRITICAL + MEDIUM abre una incidencia
`security/medium`, Checkov falla de forma estricta (los controles integrados
CKV_AWS_24/25 imponen la regla del puerto de administración). Los jobs independientes se
ejecutan en paralelo con cachés de npm/Trivy para mantenerse ≤15 min.

## Consecuencias
- (+) La puerta refleja el riesgo real de producción; las supresiones son auditables (replica la disciplina SAST exigida).
- (+) Las reglas personalizadas siguen ejercitándose de forma demostrable.
- (+) El fan-out en paralelo + el cacheo cumplen el SLA de ≤15 min.
- (−) La lista de exclusiones debe revisarse para que nunca oculte un hallazgo real de producción — bajo responsabilidad de SecOps en CODEOWNERS.
