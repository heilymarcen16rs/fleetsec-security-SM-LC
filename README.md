# FleetSec — Programa de Seguridad (Prueba Técnica · Ingeniero de Ciberseguridad)

> Solución completa a la prueba técnica de **Simon Movilidad / Quantum Data Processing**.
> Escenario: **FleetSec S.A.S.**, telemetría de flotas (+60.000 vehículos), datos
> personales bajo **Ley 1581** e **ISO 27001 en proceso**, sin programa de seguridad
> maduro y con un **breach activo** (credenciales AWS comprometidas, 45.7 GB de salida).

**Autor:** Ingeniero de Ciberseguridad (candidato) · **Fecha:** 2026-08-23
**Enlace al video (YouTube No listado):** `<<PEGAR_URL_AQUÍ>>` *(ver guion en `docs/video-script.md`)*

---

## 0. Índice de entregables

| # | Entregable | Ubicación | Estado |
|---|-----------|-----------|--------|
| 01 | Pipeline DevSecOps | `.github/workflows/devsecops.yml`, `break-glass.yml`, `semgrep/` | ✅ |
| 02 | VAPT + remediación | `app/`, `app/tests/`, `vapt/vapt-report.md` + `.pdf` | ✅ 10/10 |
| 03 | Hardening AWS (IaC) | `terraform/`, `checkov/`, `docs/compliance-matrix.md` | ✅ 251/0/12 |
| 04 | Detección e IR | `detection/sigma/`, `detection/threat-intel/`, `detection/playbooks/` | ✅ |
| 05 | Documentación | `README.md`, `docs/adr/`, `docs/diagrams/`, `docs/ai-report.md` | ✅ |
| Bonus | `docker compose up` de un comando | `docker-compose.yml` | ✅ |

**Verificación reproducible (ejecutada):** 20/20 tests (PoC+fix) · Semgrep custom
dispara solo en `/vuln` · Checkov 251 passed/0 failed · 4 reglas Sigma válidas (pysigma).

---

## 1. Análisis crítico y "trampas" de la prueba (léase primero)

Un ingeniero senior no implementa requerimientos al pie de la letra si son inseguros.
Estas son las trampas detectadas y su corrección profesional (detalle en `docs/adr/0005`).

| # | Trampa en el enunciado | Riesgo | Corrección aplicada |
|---|------------------------|--------|---------------------|
| T1 | **KMS "key policy sin Principal AWS *"** | Un `Principal:"*"` en la política de llave = acceso público a la CMK | Statement de admin al *account root* + principals de servicio scopeados; **nunca** `Principal:"*"` (`kms.tf`) |
| T2 | **"sin SG con 0.0.0.0/0 excepto 80/443 en ALB"** | Tentación de abrir de más | Solo el SG del ALB expone 0.0.0.0/0, solo 80 (redirect) y 443. Puertos admin jamás. Enforced por CKV_AWS_24/25 |
| T3 | **RDS `ssl=1`, `log_connections=1`** | Config aparentemente pedida pero fácil de omitir | Parameter group `rds.force_ssl=1` + `log_connections=1` + IAM auth + sin endpoint público (`rds.tf`) |
| T4 | **V-10: "migrar a variable de entorno o gestor de secretos — nunca mover a otro archivo del repo"** | Mover el secreto a otro `.js`/`.env` versionado sigue siendo exposición | Secreto **eliminado** del código → env/AWS Secrets Manager con rotación 30d |
| T5 | **`svc-monitoring` (cuenta de servicio) con ConsoleLogin** (línea de tiempo) | Las cuentas de servicio no deben tener consola | El playbook revoca el login profile; backlog P1 añade SCP que lo prohíbe |
| T6 | **DAST "cobertura ≥80% del OpenAPI"** sin OpenAPI provisto | Sin contrato, ZAP no cubre nada | Se publica `app/openapi.yaml` de la superficie *segura* para el escaneo autenticado |
| T7 | **Break-glass** "2 aprobadores + registro auditado" | Un bypass sin auditoría es una puerta trasera | Environment protegido (2 reviewers) + issue CRITICAL automático por cada override (`break-glass.yml`) |
| T8 | **Reporte de IA: "afirmar que no hubo errores no suma puntos"** | Tentación de decir "todo perfecto" | Se **admite** una alucinación real (digest Docker inventado) y otras; ver §6 y `docs/ai-report.md` |
| T9 | **App vulnerable pedida** (SQLi sin parametrizar, alg:none, etc.) | Construir eso y dejarlo expuesto | El laboratorio `/vuln` está *gated* (`LAB_MODE`), nunca se despliega (`LAB_MODE=false` en Docker) y convive con su gemelo `/secure` remediado |
| T10 | **"Pipeline ≤15 min" + escaneos pesados** | Un pipeline serial supera el SLA | Fan-out de jobs en paralelo + caché npm/Trivy/Semgrep + filtros de ruta |

---

## 2. Estado actual vs objetivo (as-is / to-be)

Diagramas completos (Mermaid, renderizan en GitHub): **`docs/diagrams/architecture.md`**
— incluye C4 de arquitectura objetivo con *trust boundaries*, la secuencia del breach y
el flujo del pipeline. Resumen:

| Dominio | AS-IS | TO-BE |
|--------|-------|-------|
| Identidad | IAM users, sin MFA, admin en cuentas de servicio | SSO+MFA, STS, rol por servicio, SCP |
| Edge | Sin WAF | CloudFront + WAF v2 (SQLi/bad-inputs/rate/geo) |
| Red | Plana, RDS público | VPC 3 capas, subred data aislada, RDS privado |
| Datos | AES-256 default | SSE-KMS CMK, BPA, Object Lock en logs |
| Secretos | Hardcodeados | Secrets Manager + rotación |
| Detección | Ninguna | GuardDuty + Security Hub + Sigma + Threat Intel |
| SDLC | Sin gates | Pipeline DevSecOps (SAST/SCA/DAST/IaC/secretos) |

---

## 3. Setup e instrucciones de ejecución

### 3.1 Levantar el entorno (un comando — Bonus)
```bash
docker compose up --build        # API en http://localhost:3000 (LAB_MODE=true para el demo)
curl localhost:3000/health
```

### 3.2 App y pruebas VAPT/remediación
```bash
cd app
npm ci
npm test                 # 20/20: 10 PoC (/vuln) + 10 remediaciones (/secure)
npm run test:vapt        # solo PoC de explotación
npm run test:remediation # solo pruebas de que el fix bloquea + no rompe lo legítimo
```

### 3.3 SAST (Semgrep) — reglas propias
```bash
pip install semgrep
semgrep --config semgrep/fleetsec-rules.yaml app/src          # dispara solo en /vuln y config.js
```

### 3.4 IaC (Terraform + Checkov)
```bash
cd terraform/environments/prod
terraform init -backend=false && terraform validate
cd ../../..
python3 checkov/fleetsec_sg_check.py                          # self-test de la política custom
checkov -d terraform --external-checks-dir checkov            # 251 passed / 0 failed / 12 skips
```

### 3.5 Detección (Sigma)
```bash
pip install sigma-cli
python3 -c "from sigma.collection import SigmaCollection; import glob; [SigmaCollection.from_yaml(open(f).read()) for f in glob.glob('detection/sigma/*.yml')]; print('4 reglas OK')"
```

### 3.6 Pipeline
Al hacer push a `main`/`develop` o abrir un PR se dispara `.github/workflows/devsecops.yml`.

---

## 4. Pipeline DevSecOps — diseño y optimizaciones (≤15 min)

Jobs **en paralelo** (fan-out) que convergen en el `security-gate` (fan-in):

- **A1 SAST** Semgrep (informativo full-repo + gate bloqueante en `app/src`).
- **A2 SCA + SBOM** Trivy fs (bloquea HIGH/CRITICAL) + CycloneDX en cada build.
- **B Secrets** Gitleaks (allowlist documentado para el artefacto de laboratorio V-10).
- **C Tests** 20 tests PoC+remediación.
- **D IaC** `terraform validate` + Checkov (hard-gate; bloquea SG 0.0.0.0/0 en 22/3389).
- **E Build + Image scan** Trivy imagen (bloquea CRITICAL), base pinneada, non-root.
- **F DAST** OWASP ZAP API scan autenticado (Bearer JWT) sobre el OpenAPI; HIGH/CRITICAL bloquean, MEDIUM abre issue `security/medium`.
- **G Gate** exige verde en todos.

**Optimizaciones:** paralelización, caché de npm/Trivy DB, `cancel-in-progress`,
imagen slim sin build nativo (`sql.js` WASM), escaneo incremental por severidad.

**Break-glass:** `break-glass.yml` — Environment protegido con 2 reviewers (CODEOWNERS)
+ issue CRITICAL de auditoría por cada override.

---

## 5. Cumplimiento (CIS AWS 1.4 / ISO 27001:2022 / Ley 1581)

Tabla completa con evidencia por control: **`docs/compliance-matrix.md`**
(27 PASS / 0 FAIL / 1 N/A documentado; incluye los controles nuevos 2022:
A.5.7, A.8.9, A.8.11, A.8.16, A.8.23, A.8.28).

---

## 6. Reporte de IA (obligatorio)

> Versión completa en `docs/ai-report.md`. Resumen exigido por la prueba:

**Herramientas/tareas:** IA (Claude) para generar app, reglas Semgrep/Sigma, Terraform,
CVSS, playbook y este informe. **Cada artefacto se verificó con herramientas reales**
(20 tests, Semgrep, Checkov 251/0, pysigma, calculadora CVSS 3.1, weasyprint).

**Alucinación admitida (obligatorio):** el `Dockerfile` inicial fijó la imagen base con
un **digest SHA256 inventado** (`@sha256:2f7ceb6f...`), plausible pero falso — habría
roto `docker build`. Se detectó porque un digest legítimo solo sale de
`docker inspect`/`pull`, y se corrigió a un tag pinneado real documentando el
procedimiento de endurecimiento a digest. Otros errores corregidos: reglas Semgrep que
no disparaban (→ modo taint), modificador Sigma inválido `nocase` (→ eliminado), y un
check Checkov en Python que no cargaba en el runner (→ enforcement por CKV_AWS_24/25 +
política YAML + self-test, sin ocultar la limitación).

**Qué NO delegaría a IA sin supervisión (≤150 palabras):** respuesta a incidentes en
vivo, aceptación/clasificación final de riesgo y decisiones de cumplimiento (p. ej.
notificación SIC), manejo real de secretos/llaves, aprobación de excepciones
(supresiones, break-glass) y payloads contra terceros sin autorización. La IA acelera y
detecta, pero el criterio, la rendición de cuentas y las acciones irreversibles son del
ingeniero. Además, la IA alucina (§10): todo output se verifica empíricamente.

---

## 7. Desafíos y Próximos Pasos

**Desafíos encontrados**
- Balancear un laboratorio deliberadamente vulnerable con gates que exigen 0 HIGH/CRITICAL → resuelto con supresiones documentadas y separación `/vuln` vs `/secure`.
- Reproducir XXE de forma portable sin librerías nativas → parser de laboratorio declarado explícitamente.
- Custom check de Checkov en Python no cargaba en el runner de esta versión → enforcement por checks nativos + política YAML + self-test.
- `terraform validate`/`plan` completos requieren credenciales/red no disponibles aquí → HCL validado y Checkov ejecutado sobre los 12 archivos.

**Próximos pasos (roadmap)**
- Federación OIDC para eliminar llaves estáticas de servicio; DNS Firewall (Route53) y egress firewall (Network Firewall).
- SOC/SIEM 24x7 con las reglas Sigma desplegadas y threat hunting continuo.
- Camino a certificación ISO 27001: SoA, análisis de riesgos ISO 27005, auditoría interna ISO 19011.
- Cross-region replication para el bucket de telemetría (hoy riesgo aceptado documentado).

## 8. Decisiones de arquitectura (ADRs)
`docs/adr/` — 0001 stack, 0002 gates DevSecOps, 0003 baseline Terraform,
0004 detección/IR, 0005 manejo de trampas.

## 9. Plan de sprints
`docs/sprints.md` — Sprints 0–5 con objetivos, entregables, controles y DoD.
