# ADR-0001 — Stack: Node.js 20 + Express, aplicación vulnerable mínima propia

- **Estado:** Aceptado · **Fecha:** 2026-08-23 · **Responsable:** Ingeniería de Seguridad

## Contexto
La prueba permite elegir libremente el stack y utilizar, bien una aplicación vulnerable
conocida (Juice Shop, DVWA), bien una construcción propia mínima para el VAPT. Debemos
demostrar las 10 clases CWE específicas y remediar ≥8 **en nuestro propio código** con
pruebas emparejadas maliciosas/legítimas.

## Decisión
Construir una aplicación mínima en Express (Node 20) con una superficie de laboratorio
`/vuln` (los 10 CWE) y un gemelo remediado `/secure`. Usar dependencias en JavaScript
puro (`sql.js` WASM SQLite, sin compilación nativa) para mantener la imagen Docker ligera
y el pipeline rápido.

## Consecuencias
- (+) Controlamos exactamente los 10 CWE; cada PoC y cada corrección es reproducible y está cubierta por pruebas unitarias (20/20).
- (+) La remediación reside en nuestro código (la rúbrica lo premia frente a parchear aplicaciones de terceros).
- (+) `docker compose up` es un único comando rápido (Bonus +5%).
- (−) Un laboratorio construido a mano debe documentarse de forma transparente (p. ej., el parser XXE es deliberadamente ingenuo); se deja constancia en el README y en el hallazgo.
- (−) No es un objetivo «famoso»; se mitiga mapeando cada hallazgo a OWASP/CWE y ofreciendo Juice Shop como banco de comparación opcional.
