# Guion de video — Sustentación FleetSec (≤10 min, cámara activa)

**Formato:** YouTube No listado · rostro visible toda la grabación · pantalla compartida.
**Consejo:** habla natural, no leas de corrido. Los tiempos son guía; ronda a 9:30–9:50
para dejar margen. Cada bloque indica **[EN PANTALLA]** lo que se muestra.

---

### 0:00 – 0:40 · Introducción (cámara, sin compartir aún)
> "Hola, soy **[NOMBRE]**, ingeniero de ciberseguridad. Esta es mi sustentación de la
> prueba técnica para **Simon Movilidad**. El escenario es **FleetSec**, una empresa de
> telemetría de flotas con más de 60.000 vehículos, que maneja datos personales bajo
> **Ley 1581** e **ISO 27001 en proceso**, sin un programa de seguridad maduro y — lo más
> urgente — **con un breach activo**. En los próximos diez minutos les muestro cinco
> cosas: la arquitectura de seguridad, las *trampas* que detecté en el enunciado, el
> pipeline DevSecOps corriendo, la explotación y el parcheo de dos vulnerabilidades, y mi
> respuesta al incidente de la línea de tiempo. Todo es reproducible y está verificado."

### 0:40 – 2:00 · Arquitectura de seguridad general
**[EN PANTALLA]** `docs/diagrams/architecture.md` renderizado (o el PNG de draw.io).
> "Parto de un diagnóstico **as-is vs to-be**. Hoy FleetSec tiene IAM sin MFA, admin en
> cuentas de servicio, RDS público, sin WAF y sin detección. El objetivo es esta
> arquitectura: **CloudFront con WAF v2** en el borde; una **VPC de tres capas** con la
> subred de datos totalmente aislada, sin ruta a Internet; **RDS Multi-AZ cifrado con CMK**
> y sin endpoint público; **S3 con SSE-KMS y Object Lock** para logs inmutables; secretos
> en **Secrets Manager**; y toda la telemetría de seguridad en **GuardDuty y Security Hub**.
> Fíjense en las **fronteras de confianza** en rojo: cada flecha lleva protocolo y
> autenticación. Todo esto está como **Terraform** en `modules/security-baseline`, y pasa
> Checkov con **251 controles en verde y cero fallos**."

### 2:00 – 3:20 · Las trampas del enunciado (diferenciador)
**[EN PANTALLA]** `README.md` §1 (tabla de trampas).
> "Un ingeniero senior no implementa a ciegas. El enunciado tiene trampas. Tres ejemplos:
> Primero, pedía una **política de KMS sin `Principal AWS *`** — si uno pone un comodín en
> la política de la llave, la vuelve pública; yo la scopeé al *account root* y a los
> servicios necesarios. Segundo, en la remediación de credenciales embebidas advierte
> *'nunca mover el secreto a otro archivo del repo'* — moverlo a un `.env` versionado sigue
> siendo exposición, así que lo **saqué del código** hacia Secrets Manager. Y tercero, el
> **break-glass**: un bypass sin auditoría es una puerta trasera, por eso el mío exige **dos
> aprobadores** y abre un **issue crítico de auditoría** automáticamente. Documenté las diez
> trampas en el README y en el ADR-0005."

### 3:20 – 5:20 · Pipeline DevSecOps en ejecución (demo)
**[EN PANTALLA]** pestaña Actions de GitHub con un run reciente; luego `devsecops.yml`.
> "Este es el pipeline corriendo. Vean que los stages van **en paralelo** — SAST, SCA,
> secretos, tests, IaC — y convergen en un **security-gate** final. Corre en **menos de 15
> minutos** gracias a la paralelización y al caché."
**[EN PANTALLA]** abrir el job **A1 SAST** y mostrar Semgrep.
> "Aquí Semgrep con mis **cuatro reglas propias**. Uso *taint mode*: rastrea el dato desde
> `req.query` hasta el sink peligroso, así dispara en el código vulnerable y **no** en el
> remediado — cero falsos positivos."
**[EN PANTALLA]** job **D IaC** (Checkov) y **A2** (SBOM).
> "El stage de IaC bloquea, por ejemplo, cualquier grupo de seguridad que abra SSH o RDP a
> Internet. Y cada build exitoso genera el **SBOM en CycloneDX**."
**[EN PANTALLA]** correr localmente `cd app && npm test`.
> "Y localmente: **veinte pruebas en verde** — diez que explotan y diez que confirman el
> parche. Esto es lo que da confianza de que las remediaciones funcionan."

### 5:20 – 7:20 · Walkthrough de 2 vulnerabilidades (explotación + parche)
**[EN PANTALLA]** `app/src/routes/vulnerable.js` (V-01) y el test.
> "Vulnerabilidad uno: **inyección SQL**, CVSS 9.8. El endpoint concatena el parámetro `id`
> directo en la consulta. Con un `UNION SELECT` extraigo el `api_secret` de otro usuario
> — aquí está el PoC pasando."
**[EN PANTALLA]** `app/src/routes/secure.js` (V-01) y el test de remediación.
> "El parche: **consulta parametrizada** con *prepared statement* y validación de entero.
> El test confirma dos cosas: el payload malicioso ahora da 400, y la consulta legítima
> sigue funcionando. Ese doble test evita que un fix rompa a los usuarios reales."
**[EN PANTALLA]** `app/src/lib/jwt.js` y el test V-02.
> "Vulnerabilidad dos: **JWT con `alg:none`**, CVSS 9.1. El verificador confía en el header
> del cliente, así que forjo un token de administrador sin firma. El parche fija una
> **allowlist de algoritmos** — `none` deja de ser aceptable. Otra vez, verificado con
> token forjado rechazado y token real aceptado."

### 7:20 – 9:10 · Respuesta al breach de la línea de tiempo
**[EN PANTALLA]** `detection/playbooks/ir-playbook.md` (timeline + CLI).
> "Ahora el incidente. La línea de tiempo muestra un login desde **Tor** con credenciales
> válidas, escalamiento a admin de `svc-monitoring`, **387 GetObject en 8 minutos** — 45.7
> GB de datos de conductores — y un intento de **borrar CloudTrail que el SCP bloqueó**.
> Mi playbook sigue **NIST 800-61**: primero preservo evidencia — snapshots y volcado de
> memoria **antes** de tocar la red —, luego contengo: desactivo llaves, **revoco las
> sesiones STS con `aws:TokenIssueTime`**, aíslo la instancia y bloqueo la IP en el WAF.
> Cada comando es exacto y reversible."
**[EN PANTALLA]** `detection/sigma/` y la tabla MITRE del playbook.
> "De este incidente derivo **cuatro reglas Sigma** — validadas — para detectarlo más
> rápido la próxima vez, y mapeo **ocho técnicas de MITRE ATT&CK**. El análisis de causa
> raíz con 5-Whys llega al verdadero origen: **no faltaba una política, faltaba un proceso**
> de revisión periódica de controles."
**[EN PANTALLA]** el resumen ejecutivo para el CEO y la sección Ley 1581.
> "Cierro con lo que la dirección necesita: un **resumen ejecutivo de una página sin
> tecnicismos**, y el deber legal — al haber datos personales, hay que **notificar a la SIC
> en 15 días hábiles** bajo Ley 1581."

### 9:10 – 9:50 · Sprints, IA y cierre
**[EN PANTALLA]** `docs/sprints.md` y `docs/ai-report.md`.
> "Organicé todo en **seis sprints**, del 0 al 5, cada uno con su *Definition of Done*. Y
> sobre el uso de IA: fui honesto — la IA me **alucinó un digest de Docker inventado** que
> habría roto el build; lo detecté porque un digest solo sale de `docker inspect`, no de la
> memoria. Todo lo generado por IA lo verifiqué con herramientas reales. En resumen:
> pipeline funcional, diez vulnerabilidades remediadas, infraestructura endurecida,
> detección y respuesta listas, y criterio de seguridad por encima del cumplimiento
> literal. Gracias — quedo atento a sus preguntas."

---

## Checklist antes de grabar
- [ ] Cámara encendida y rostro visible durante **toda** la grabación (requisito).
- [ ] Repo ya pusheado; un run del pipeline visible en Actions.
- [ ] `npm test` probado en local (para el demo en vivo).
- [ ] Diagramas renderizados (GitHub o PNG de draw.io) listos en pestañas.
- [ ] Duración final ≤ 10:00. Subir a YouTube como **No listado** y pegar el link en el README.
