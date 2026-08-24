# Instrucciones de Ejecución para el Candidato

Todo lo que la IA no puede hacer por ti (crear el repo remoto, grabar el video,
generar el PNG de draw.io, ejecutar en tu nube) queda aquí, paso a paso.

---

## A. Publicar el repositorio con commits atómicos (Conventional Commits)

> **Requisito de la prueba:** "un único commit descarta la candidatura". El repo se
> entrega con un historial atómico ya preparado. Solo tienes que crear el remoto y hacer push.

### A.1 Si recibiste el ZIP (sin `.git`)
Ejecuta el script incluido, que crea el historial atómico automáticamente:
```bash
cd fleetsec-security
bash scripts/init-git-history.sh          # crea ~15 commits atómicos Conventional Commits
```

### A.2 Crear el repositorio remoto y hacer push
```bash
# Opción GitHub CLI (recomendada)
gh repo create fleetsec-security --private --source=. --remote=origin --push
# o manual:
git remote add origin git@github.com:<tu-usuario>/fleetsec-security.git
git branch -M main
git push -u origin main
```
Para revisor externo: `Settings → Collaborators` (privado con acceso) o hazlo público.

### A.3 Verificar los gates antes de entregar
```bash
gh workflow run "DevSecOps Pipeline" ; gh run watch      # o abre la pestaña Actions
```

---

## B. Generar el diagrama en draw.io a partir del Mermaid

El repo trae los diagramas en Mermaid (`docs/diagrams/architecture.md`), que ya
renderizan en GitHub. Para el artefacto draw.io/PNG:

1. Abre **https://app.diagrams.net** (draw.io).
2. `Extras → Edit Diagram...` **no** — usa: `Arrange → Insert → Advanced → Mermaid...`
   (en versiones nuevas: `+ (Insert) → Mermaid`).
3. Pega el bloque Mermaid de la sección 2 (C4 objetivo) de `architecture.md` (solo el
   contenido entre ```mermaid y ```), y pulsa **Insert**.
4. Ajusta posición si quieres; añade los iconos oficiales de AWS con
   `More Shapes... → Networking → AWS 2019`.
5. Exporta: `File → Export as → PNG` (marca *Transparent* off, *Border* 10) y también
   `File → Export as → XML` (`.drawio`) para dejar la fuente editable.
6. Guarda como `docs/diagrams/architecture.drawio` y `docs/diagrams/architecture.png`,
   commitea y actualiza el enlace en el README si lo deseas.

> Consejo: repite para la secuencia del breach (sección 3) si quieres un diagrama de
> flujo del incidente en el video.

---

## C. Grabar y publicar el video (YouTube No listado, ≤10 min, con cámara)

1. **Guion:** `docs/video-script.md` (palabra por palabra, con marcas de tiempo).
2. **Herramienta de grabación:** OBS Studio (gratis) o Loom.
   - En OBS: una *Scene* con **Display Capture** (pantalla) + **Video Capture Device**
     (webcam) en una esquina. La cámara debe verse **toda** la grabación (requisito).
   - Resolución 1080p, 30 fps; micrófono probado.
3. **Antes de grabar** ejecuta el checklist al final del guion (pipeline visible,
   `npm test` listo para el demo en vivo, diagramas abiertos en pestañas).
4. **Graba** siguiendo el guion; apunta a 9:30–9:50 para no pasarte de 10:00.
5. **Publica en YouTube:**
   - `Subir video → Visibilidad: **No listado (Unlisted)**` (NO privado, NO público).
   - Título sugerido: *"FleetSec — Prueba Técnica Ciberseguridad — [Tu Nombre]"*.
   - Copia el enlace y **pégalo en el README** (campo `<<PEGAR_URL_AQUÍ>>` de la cabecera).

---

## D. (Opcional) Probar contra tu propia nube AWS

No se requiere cuenta AWS para la prueba, pero si quieres validar el Terraform:
```bash
cd terraform/environments/prod
terraform init                      # con backend S3 real (descomenta el bloque backend)
terraform plan                      # revisa el plan; NO apliques en una cuenta productiva sin revisar costos
```
El `aws_guardduty_threatintelset` y el WAF incurren costos; usa una cuenta sandbox.

---

## E. Checklist final de entrega

- [ ] Repo público (o privado con acceso al revisor), con historial de commits atómicos.
- [ ] Pipeline visible en verde en Actions.
- [ ] `vapt/vapt-report.pdf` presente.
- [ ] Video No listado subido y **enlace pegado en el README**.
- [ ] README con: setup, diagrama as-is/to-be, ADRs, enlace al video, Reporte de IA, Desafíos y Próximos Pasos.
- [ ] `docs/diagrams/architecture.png` (draw.io) generado.
